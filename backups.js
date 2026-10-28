/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// Metadata only. Snapshot contents, Telegram tokens and root paths never enter
// this tab. A lost create response keeps its request key until the user reviews
// the list and explicitly confirms a retry.
const backupsClient = { generation: 0, listSeq: 0, ids: [], details: new Map(),
  listKnown: false, loading: false, creating: false, checking: null,
  visible: 40, pending: null, uncertainKey: null };
const BACKUP_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const BACKUP_MAX_BYTES = 4 * 1024 ** 3;

function backupsCurrent(generation, token, base) {
  return backupsClient.generation === generation && state.token === token && state.base === base &&
    Boolean(token) && hubCanGlobalAdmin();
}

function backupsReset() {
  backupsClient.generation++;
  backupsClient.listSeq++;
  Object.assign(backupsClient, { ids: [], details: new Map(), listKnown: false,
    loading: false, creating: false, checking: null, visible: 40,
    pending: null, uncertainKey: null });
  if ($("backupsCreateDialog").open) $("backupsCreateDialog").close();
  globalThis.backupsRestoreReset?.();
  $("backupsStatus").textContent = "Откройте настройки, чтобы проверить копии.";
  clearError($("backupsError"));
  clearError($("backupsCreateError"));
  backupsRender();
}
globalThis.backupsReset = backupsReset;

function backupsDetail(value, expectedId = null) {
  const detail = value?.backup;
  if (!detail || typeof detail !== "object" || Array.isArray(detail) ||
      !BACKUP_UUID.test(detail.id) || (expectedId !== null && detail.id !== expectedId) ||
      !Number.isSafeInteger(detail.created_at) || detail.created_at < 1 ||
      detail.created_at > 253402300799 || !Number.isSafeInteger(detail.database_bytes) ||
      detail.database_bytes < 1 || detail.database_bytes > BACKUP_MAX_BYTES ||
      typeof detail.telegram_token_included !== "boolean" || detail.verified !== true ||
      Object.keys(detail).length !== 5) {
    throw new Error("Hub вернул неверное описание резервной копии.");
  }
  return detail;
}

function backupsRender() {
  const client = backupsClient;
  const ready = hubCanGlobalAdmin() && Boolean(state.token);
  $("backupsCount").textContent = client.listKnown ? String(client.ids.length) : "—";
  $("backupsReload").disabled = !ready || client.loading || client.creating;
  $("backupsCreate").disabled = !ready || !client.listKnown || client.loading ||
    client.creating || Boolean(client.checking) || globalThis.backupsRestoreCanStart?.() === false;
  $("backupsCreate").textContent = client.uncertainKey ? "Проверить создание" : "Создать копию";
  const list = $("backupsList"); list.replaceChildren();
  $("backupsMore").hidden = !client.listKnown || client.ids.length <= client.visible;
  if (!client.listKnown) return;
  if (!client.ids.length) {
    const empty = document.createElement("p"); empty.className = "no-incidents";
    empty.textContent = "Копий пока нет."; list.append(empty);
  }
  for (const id of client.ids.slice(0, client.visible)) {
    const detail = client.details.get(id);
    const card = document.createElement("article"); card.className = "backup-card";
    const content = document.createElement("div");
    const heading = document.createElement("strong");
    heading.textContent = detail ? `Копия от ${timestamp(detail.created_at)}` : `Копия ${id.slice(0, 8)}`;
    const description = document.createElement("p");
    description.textContent = detail
      ? `${bytes(detail.database_bytes)} · Telegram-токен ${detail.telegram_token_included ? "включён" : "не настроен"} · проверена`
      : `ID: ${id} · сведения появятся после проверки`;
    content.append(heading, description);
    const button = document.createElement("button"); button.type = "button";
    button.className = "secondary-button";
    button.textContent = client.checking === id ? "Проверяем…" : "Проверить";
    button.disabled = !ready || Boolean(client.checking) || client.creating;
    button.addEventListener("click", () => { void backupsVerify(id); });
    const actions = document.createElement("div"); actions.className = "backup-card-actions";
    actions.append(button);
    if (detail) {
      const restore = document.createElement("button"); restore.type = "button";
      restore.className = "secondary-button"; restore.textContent = "Восстановить…";
      restore.disabled = !ready || Boolean(client.checking) || client.creating ||
        globalThis.backupsRestoreCanStart?.() === false;
      restore.addEventListener("click", () => { void globalThis.backupsPrepareRestore?.(id); });
      actions.append(restore);
    }
    card.append(content, actions); list.append(card);
  }
  $("backupsMore").disabled = !ready || client.loading || client.creating;
}

async function backupsRefresh() {
  if (!state.token || !hubCanGlobalAdmin() || backupsClient.loading || backupsClient.creating) return;
  const generation = backupsClient.generation, token = state.token, base = state.base;
  const sequence = ++backupsClient.listSeq;
  backupsClient.loading = true;
  backupsRender();
  try {
    const result = await request("/api/v1/backups", { timeoutMs: 16000 });
    if (!backupsCurrent(generation, token, base) || sequence !== backupsClient.listSeq) return;
    const ids = result?.ids;
    if (!Array.isArray(ids) || ids.length > 1000 || ids.some((id) => !BACKUP_UUID.test(id)) ||
        new Set(ids).size !== ids.length) throw new Error("Hub вернул неверный список копий.");
    backupsClient.ids = ids;
    backupsClient.details = new Map([...backupsClient.details].filter(([id]) => ids.includes(id)));
    backupsClient.listKnown = true;
    $("backupsStatus").textContent = backupsClient.uncertainKey
      ? "Список обновлён. Прежний запрос мог ещё выполняться. Проверьте копии; повторное нажатие использует тот же ключ и не создаст дубль."
      : `Найдено копий: ${ids.length}. Проверка открывает только дату, размер и признак токена.`;
    clearError($("backupsError"));
    globalThis.backupsRestoresMaybeRefresh?.();
  } catch (error) {
    if (!backupsCurrent(generation, token, base) || sequence !== backupsClient.listSeq) return;
    backupsClient.listKnown = false;
    const message = error.status === 404 ? "Обновите Hub, чтобы видеть резервные копии в панели." :
      error.status === 503 ? "Серверный брокер копий пока не включён. Проверьте установку Hub." :
        error.message || "Не удалось получить список копий.";
    showError($("backupsError"), message);
    $("backupsStatus").textContent = "Список не подтверждён.";
  } finally {
    if (backupsCurrent(generation, token, base) && sequence === backupsClient.listSeq) {
      backupsClient.loading = false; backupsRender();
    }
  }
}
globalThis.backupsRefresh = backupsRefresh;

async function backupsVerify(id) {
  if (!BACKUP_UUID.test(id) || !backupsClient.ids.includes(id) || !backupsClient.listKnown ||
      !state.token || !hubCanGlobalAdmin() || backupsClient.checking || backupsClient.creating) return;
  const generation = backupsClient.generation, token = state.token, base = state.base;
  backupsClient.checking = id;
  $("backupsStatus").textContent = "Проверяем целостность копии; это может занять несколько минут…";
  clearError($("backupsError"));
  backupsRender();
  try {
    const detail = backupsDetail(await request(`/api/v1/backups/${id}`, { timeoutMs: 600000 }), id);
    if (!backupsCurrent(generation, token, base)) return;
    backupsClient.details.set(id, detail);
    $("backupsStatus").textContent = `Копия ${id.slice(0, 8)} проверена: ${timestamp(detail.created_at)}, ${bytes(detail.database_bytes)}.`;
  } catch (error) {
    if (backupsCurrent(generation, token, base))
      showError($("backupsError"), error.status === 404 ? "Копия больше не найдена. Обновите список." :
        error.status === 503 ? "Проверка копии недоступна. Попробуйте позже." :
          error.message || "Не удалось проверить копию.");
  } finally {
    if (backupsCurrent(generation, token, base)) { backupsClient.checking = null; backupsRender(); }
  }
}

function backupsPrepareCreate() {
  if (!state.token || !hubCanGlobalAdmin() || !backupsClient.listKnown ||
      backupsClient.loading || backupsClient.creating || backupsClient.checking ||
      globalThis.backupsRestoreCanStart?.() === false) return;
  let key = backupsClient.uncertainKey;
  if (!key) {
    try { key = crypto.randomUUID(); } catch {
      showError($("backupsError"), "Не удалось создать ключ запроса. Откройте панель через HTTPS или localhost.");
      return;
    }
  }
  if (!BACKUP_UUID.test(key)) return;
  backupsClient.pending = { key, generation: backupsClient.generation,
    token: state.token, base: state.base };
  $("backupsCreateHeading").textContent = backupsClient.uncertainKey
    ? "Проверить прежний запрос?" : "Создать копию Hub?";
  $("backupsCreateDescription").textContent = backupsClient.uncertainKey
    ? "Ответ на прошлый запрос потерян. Список уже обновлён; при подтверждении Hub получит тот же ключ запроса и вернёт прежний результат, если копия уже создана."
    : "Снимок базы и настроенного Telegram-токена будет сохранён в закрытом каталоге этого сервера. Операция может занять несколько минут; после создания копия будет проверена.";
  $("backupsCreateConfirm").textContent = backupsClient.uncertainKey ? "Проверить запрос" : "Создать";
  clearError($("backupsCreateError"));
  $("backupsCreateDialog").showModal();
}

async function backupsConfirmCreate() {
  const pending = backupsClient.pending;
  if (!pending || !backupsCurrent(pending.generation, pending.token, pending.base) ||
      !backupsClient.listKnown || backupsClient.loading || backupsClient.creating ||
      globalThis.backupsRestoreCanStart?.() === false) return;
  backupsClient.pending = null;
  $("backupsCreateDialog").close();
  backupsClient.creating = true;
  $("backupsStatus").textContent = "Создаём и проверяем копию. Можно открыть другой раздел; операция продолжится на сервере…";
  clearError($("backupsError"));
  backupsRender();
  let uncertain = false;
  try {
    const result = await request("/api/v1/backups", {
      method: "POST", headers: { "Idempotency-Key": pending.key }, body: "{}", timeoutMs: 900000,
    });
    if (!backupsCurrent(pending.generation, pending.token, pending.base)) return;
    const detail = backupsDetail(result);
    backupsClient.uncertainKey = null;
    backupsClient.details.set(detail.id, detail);
    $("backupsStatus").textContent = `Копия создана и проверена: ${timestamp(detail.created_at)}, ${bytes(detail.database_bytes)}.`;
  } catch (error) {
    if (!backupsCurrent(pending.generation, pending.token, pending.base)) return;
    // A broker can lose its own response after creating the snapshot and
    // return HTTP 503. Keep this key for every ambiguous transport outcome.
    uncertain = error.status === undefined || error.status === 503;
    if (uncertain) {
      backupsClient.uncertainKey = pending.key;
      backupsClient.listKnown = false;
      showError($("backupsError"), "Ответ потерян. Копия могла появиться; сначала обновите список. Повторный запрос возможен только после нового подтверждения и использует тот же ключ.");
    } else {
      showError($("backupsError"), error.status === 429 ? "Новая копия будет доступна через несколько минут. Существующие можно проверить сейчас." :
        error.status === 409 ? "Копию нельзя создать сейчас: идёт другая операция или требуется внимание администратора сервера." :
        error.message || "Не удалось создать копию. Проверьте список перед новой попыткой.");
    }
  } finally {
    if (backupsCurrent(pending.generation, pending.token, pending.base)) {
      backupsClient.creating = false;
      backupsRender();
      if (uncertain) void backupsRefresh();
      else if (!backupsClient.uncertainKey) void backupsRefresh();
    }
  }
}

$("backupsReload").addEventListener("click", () => { void backupsRefresh(); });
$("backupsCreate").addEventListener("click", backupsPrepareCreate);
$("backupsCreateConfirm").addEventListener("click", () => { void backupsConfirmCreate(); });
$("backupsCreateCancel").addEventListener("click", () => { if (!backupsClient.creating) $("backupsCreateDialog").close(); });
$("backupsCreateDialog").addEventListener("close", () => { backupsClient.pending = null; });
$("backupsMore").addEventListener("click", () => {
  backupsClient.visible = Math.min(backupsClient.visible + 40, backupsClient.ids.length);
  backupsRender();
});

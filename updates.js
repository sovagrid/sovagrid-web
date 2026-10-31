/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// The host owns the signed-feed configuration. Keep only a read-only snapshot
// in this tab; every change is checked against its revision by the root broker.
const releaseFeedClient = { generation: 0, loading: false, busy: false,
  status: null, pending: null, error: "", errorFromAction: false,
  blockReason: null, lastRefresh: 0 };
const RELEASE_FEED_SHA = /^[0-9a-f]{64}$/;
const RELEASE_FEED_KEY_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const RELEASE_FEED_VERSION = /^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$/;

function releaseFeedSnapshot(value) {
  const ledger = value?.ledger, keys = value?.available_keys;
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      value.format !== 1 || value.channel !== "stable" ||
      typeof value.enabled !== "boolean" ||
      typeof value.timer_installed !== "boolean" ||
      typeof value.timer_enabled !== "boolean" ||
      typeof value.timer_active !== "boolean" ||
      typeof value.manual_candidate_active !== "boolean" ||
      !RELEASE_FEED_SHA.test(value.state_revision) ||
      (value.installed_manifest_sha256 !== null &&
        !RELEASE_FEED_SHA.test(value.installed_manifest_sha256)) ||
      (value.key_id !== null && !RELEASE_FEED_KEY_ID.test(value.key_id)) ||
      !keys || typeof keys !== "object" || Array.isArray(keys) ||
      Object.keys(keys).length > 8 || Object.entries(keys).some(([id, fingerprint]) =>
        !RELEASE_FEED_KEY_ID.test(id) || !RELEASE_FEED_SHA.test(fingerprint)) ||
      !ledger || typeof ledger !== "object" || Array.isArray(ledger) ||
      ledger.format !== 1 || !Number.isSafeInteger(ledger.highest_sequence) ||
      ledger.highest_sequence < 0 || !RELEASE_FEED_VERSION.test(ledger.highest_version) ||
      !Number.isSafeInteger(ledger.highest_issued_at) || ledger.highest_issued_at < 0 ||
      !Number.isSafeInteger(ledger.last_seen_at) || ledger.last_seen_at < 0)
    throw new Error("Hub вернул неверное состояние обновлений.");
  return value;
}

function releaseFeedCurrent(generation, token, base) {
  return releaseFeedClient.generation === generation && state.token === token &&
    state.base === base && Boolean(token) && hubCanGlobalAdmin();
}

function releaseFeedDate(seconds) {
  if (!seconds) return "Пока не было";
  const date = new Date(seconds * 1000);
  return Number.isFinite(date.getTime()) && date.getUTCFullYear() < 10000
    ? date.toLocaleString("ru-RU", { timeZone: "UTC" }) + " UTC" : "Недоступно";
}

function releaseFeedExplain(error, action = false) {
  const code = error?.message;
  if (error?.status === 409 && code === "STATE_CHANGED")
    return "Состояние обновлений изменилось. Загрузите его заново и повторите подтверждение.";
  if (error?.status === 409 && code === "HUB_ONLY_UNSUPPORTED")
    return "Этот узел работает в режиме «только Hub». Автоматическая подписка для него пока недоступна; существующий Agent не затронут.";
  if (error?.status === 503 && code === "UNCONFIGURED_TRUST")
    return "На сервере нет проверенного ключа подписи для этого канала. Обновите SovaGrid и попробуйте снова.";
  if (error?.status === 503 && code === "TIMER_UNAVAILABLE")
    return "Системный таймер не запустился. Подписка осталась выключенной или требует проверки состояния.";
  if (error?.status === 503 && code === "FEED_UNAVAILABLE")
    return action
      ? "Результат операции не подтверждён: лента или связь с сервером недоступна. Проверьте обновлённое состояние перед повтором."
      : "Подписанная лента пока недоступна или выпуск для этого сервера не найден.";
  if (error?.status === 404) return "Обновите Hub, чтобы управлять подпиской из панели.";
  if (error?.status === 401 || error?.status === 403)
    return "Для управления обновлениями нужен полный доступ администратора этого Hub.";
  if (action) return "Результат операции не подтверждён. Состояние будет загружено заново; повторяйте действие только после проверки.";
  return "Не удалось проверить обновления. Повторите после восстановления связи с Hub.";
}

function releaseFeedRender() {
  const client = releaseFeedClient, value = client.status;
  const ready = Boolean(state.token) && hubCanGlobalAdmin();
  const badge = document.getElementById("releaseFeedBadge");
  badge.className = "status-badge " + (value?.enabled && value.timer_active ? "ok" :
    value?.enabled ? "warning" : value ? "waiting" : "waiting");
  badge.textContent = client.loading && !value ? "Проверяем" :
    value?.enabled && value.timer_active ? "Включено" : value?.enabled ? "Нужна проверка" :
      value ? "Выключено" : "Нет данных";
  const summary = document.getElementById("releaseFeedSummary");
  summary.textContent = !value ? "Состояние подписки пока недоступно." :
    value.enabled && value.timer_active ? "Сервер проверяет подписанные выпуски автоматически." :
      value.enabled ? "Подписка включена, но таймер проверки не работает. Проверьте состояние сервера." :
        "Автоматическая проверка подписанных выпусков выключена.";
  document.getElementById("releaseFeedVersion").textContent =
    !value ? "—" : value.ledger.highest_sequence ? value.ledger.highest_version : "Нет истории";
  document.getElementById("releaseFeedKey").textContent = value?.key_id ||
    (!value ? "—" : Object.keys(value.available_keys).length ? "Доступен, не выбран" : "Нет доверенного ключа");
  document.getElementById("releaseFeedLastSeen").textContent =
    value ? releaseFeedDate(value.ledger.last_seen_at) : "—";
  document.getElementById("releaseFeedManifest").textContent =
    value?.installed_manifest_sha256 || "—";
  document.getElementById("releaseFeedFingerprint").textContent =
    value?.key_id ? value.available_keys[value.key_id] || "Ключ больше не доступен" :
      value && Object.values(value.available_keys).length === 1
        ? Object.values(value.available_keys)[0] : "—";
  const notes = [];
  if (value && !value.timer_installed) notes.push("Службы обновления на этом сервере ещё не установлены.");
  if (value && !Object.keys(value.available_keys).length) notes.push("Нет доверенного ключа подписи.");
  if (value?.manual_candidate_active) notes.push("Уже подготовлено отдельное ручное обновление; подписка его не заменит.");
  if (client.blockReason === "HUB_ONLY_UNSUPPORTED") notes.push("Режим «только Hub» не поддерживает эту подписку.");
  if (value && !value.enabled && value.timer_installed && Object.keys(value.available_keys).length &&
      client.blockReason !== "HUB_ONLY_UNSUPPORTED")
    notes.push("При включении панель проверит доступность ленты, подпись и совместимость пакета. Пока подтверждение не выполнено, ничего не меняется.");
  document.getElementById("releaseFeedNotice").textContent = notes.join(" ");
  const locked = !ready || client.loading || client.busy || Boolean(client.pending);
  document.getElementById("releaseFeedReload").disabled = !ready || client.loading || client.busy;
  document.getElementById("releaseFeedEnable").disabled = locked || !value || value.enabled ||
    !value.timer_installed || !Object.keys(value.available_keys).length ||
    client.blockReason === "HUB_ONLY_UNSUPPORTED";
  document.getElementById("releaseFeedDisable").disabled = locked || !value?.enabled;
  const review = document.getElementById("releaseFeedReview");
  review.hidden = !client.pending;
  if (client.pending) {
    const enable = client.pending.action === "enable";
    document.getElementById("releaseFeedReviewTitle").textContent =
      enable ? "Включить автоматическую проверку?" : "Отключить автоматическую проверку?";
    document.getElementById("releaseFeedReviewText").textContent = enable
      ? "Сервер проверит подпись и совместимость текущего выпуска. После включения новые подходящие выпуски смогут устанавливаться автоматически; службы могут кратко перезапускаться."
      : "Проверка новых выпусков остановится. Уже подготовленное ручное обновление останется отдельно.";
  }
  document.getElementById("releaseFeedApply").disabled = !client.pending || !ready ||
    client.busy || !document.getElementById("releaseFeedConfirm").checked;
  document.getElementById("releaseFeedCancel").disabled = client.busy;
  const error = document.getElementById("releaseFeedError");
  error.textContent = client.error; error.hidden = !client.error;
}

function releaseFeedReset() {
  releaseFeedClient.generation++;
  Object.assign(releaseFeedClient, { loading: false, busy: false, status: null,
    pending: null, error: "", errorFromAction: false, blockReason: null, lastRefresh: 0 });
  document.getElementById("releaseFeedConfirm").checked = false;
  releaseFeedRender();
}
globalThis.releaseFeedReset = releaseFeedReset;
globalThis.releaseFeedAccessChanged = () => {
  if (!hubCanGlobalAdmin()) releaseFeedReset();
};

async function releaseFeedRefresh(force = false) {
  const client = releaseFeedClient;
  if (!state.token || !hubCanGlobalAdmin() || client.loading || client.busy) return;
  if (!force && Date.now() - client.lastRefresh < 30000) return;
  const generation = client.generation, token = state.token, base = state.base;
  client.loading = true; client.lastRefresh = Date.now(); releaseFeedRender();
  try {
    const value = releaseFeedSnapshot(await request("/api/v1/release-feed", { timeoutMs: 20000 }));
    if (!releaseFeedCurrent(generation, token, base)) return;
    if (client.status && client.status.state_revision !== value.state_revision)
      client.blockReason = null;
    if (client.pending && client.pending.revision !== value.state_revision) {
      client.pending = null;
      document.getElementById("releaseFeedConfirm").checked = false;
      client.error = "Состояние обновлений изменилось. Повторите подтверждение.";
      client.errorFromAction = true;
    }
    client.status = value;
    if (!client.errorFromAction) client.error = "";
  } catch (error) {
    if (!releaseFeedCurrent(generation, token, base)) return;
    client.status = null;
    client.pending = null;
    if (!client.errorFromAction) client.error = releaseFeedExplain(error);
  } finally {
    if (releaseFeedCurrent(generation, token, base)) {
      client.loading = false;
      releaseFeedRender();
    }
  }
}
globalThis.releaseFeedRefresh = releaseFeedRefresh;

function releaseFeedReview(action) {
  const client = releaseFeedClient;
  if (!state.token || !hubCanGlobalAdmin() || client.loading || client.busy ||
      !client.status || !RELEASE_FEED_SHA.test(client.status.state_revision) ||
      !["enable", "disable"].includes(action) ||
      (action === "enable" && (client.status.enabled || !client.status.timer_installed ||
        !Object.keys(client.status.available_keys).length ||
        client.blockReason === "HUB_ONLY_UNSUPPORTED")) ||
      (action === "disable" && !client.status.enabled)) return;
  client.pending = { action, revision: client.status.state_revision };
  client.error = "";
  client.errorFromAction = false;
  document.getElementById("releaseFeedConfirm").checked = false;
  releaseFeedRender();
}

async function releaseFeedApply() {
  const client = releaseFeedClient, pending = client.pending;
  if (!pending || client.busy || !state.token || !hubCanGlobalAdmin() ||
      !document.getElementById("releaseFeedConfirm").checked ||
      pending.revision !== client.status?.state_revision) return;
  const generation = client.generation, token = state.token, base = state.base;
  client.busy = true; client.error = ""; releaseFeedRender();
  let failed = false;
  try {
    const reply = releaseFeedSnapshot(await request(
      `/api/v1/release-feed/${pending.action}`,
      { method: "POST", body: JSON.stringify({ expected_state: pending.revision }), timeoutMs: 45000 }));
    if (!releaseFeedCurrent(generation, token, base)) return;
    client.status = reply;
    client.blockReason = null;
    client.error = "";
    client.errorFromAction = false;
    client.pending = null;
    client.lastRefresh = Date.now();
    document.getElementById("releaseFeedConfirm").checked = false;
  } catch (error) {
    if (!releaseFeedCurrent(generation, token, base)) return;
    client.error = releaseFeedExplain(error, true);
    client.errorFromAction = true;
    if (error?.message === "HUB_ONLY_UNSUPPORTED" && error.status === 409)
      client.blockReason = "HUB_ONLY_UNSUPPORTED";
    client.status = null;
    client.pending = null;
    document.getElementById("releaseFeedConfirm").checked = false;
    failed = true;
  } finally {
    if (releaseFeedCurrent(generation, token, base)) {
      client.busy = false; releaseFeedRender();
      if (failed) void releaseFeedRefresh(true);
    }
  }
}

document.getElementById("releaseFeedReload").addEventListener("click", () => {
  releaseFeedClient.error = "";
  releaseFeedClient.errorFromAction = false;
  void releaseFeedRefresh(true);
});
document.getElementById("releaseFeedEnable").addEventListener("click", () => releaseFeedReview("enable"));
document.getElementById("releaseFeedDisable").addEventListener("click", () => releaseFeedReview("disable"));
document.getElementById("releaseFeedConfirm").addEventListener("change", releaseFeedRender);
document.getElementById("releaseFeedCancel").addEventListener("click", () => {
  releaseFeedClient.pending = null;
  document.getElementById("releaseFeedConfirm").checked = false;
  releaseFeedRender();
});
document.getElementById("releaseFeedApply").addEventListener("click", () => { void releaseFeedApply(); });
releaseFeedRender();

/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// Loaded after public-web.js. Shared path rules keep both address forms in sync.
const localWebClient = { generation: 0, refreshSeq: 0, status: null, preview: null,
  pending: null, publicActive: false, dirty: false, originalHash: null, conflict: false,
  loading: false, previewing: false, applying: false, applyConflict: false,
  checking: false, checks: 0, timer: null, discoveryTimer: null,
  discoveryAttempts: 0, discoveryPath: null,
  message: "", recoveryMessage: "", repeatAllowed: false };
const LOCAL_WEB_KEY = "sovagrid.local-web.pending.v1";
const LOCAL_WEB_URL = "http://127.0.0.1:8766";
const LOCAL_WEB_ROOT_LABELS = { ...PUBLIC_WEB_ROOT_LABELS, untouched: "Оставить / как сейчас" };

function localWebConfig(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).sort().join(",") !== "panel_path,root_behavior" ||
      typeof value.panel_path !== "string" || value.panel_path.length > 96 ||
      !PUBLIC_WEB_PATH.test(value.panel_path) ||
      ["api", "healthz"].includes(value.panel_path.split("/")[1]) ||
      !Object.hasOwn(PUBLIC_WEB_ROOT_LABELS, value.root_behavior))
    throw new Error("Укажите путь из 1–3 сегментов и выберите поведение корня.");
  return { panel_path: value.panel_path, root_behavior: value.root_behavior };
}

function localWebEqual(a, b) {
  return Boolean(a && b && a.panel_path === b.panel_path && a.root_behavior === b.root_behavior);
}

function localWebStatusReply(value) {
  if (!value || Object.keys(value).sort().join(",") !==
      "config,enabled,expected_state_sha256,ok,protocol" || value.protocol !== 1 ||
      value.ok !== true || typeof value.enabled !== "boolean" ||
      !(value.expected_state_sha256 === null || PUBLIC_WEB_HASH.test(value.expected_state_sha256)))
    throw new Error("Hub вернул неверное состояние локального пути.");
  if (value.enabled) {
    localWebConfig(value.config);
    if (value.expected_state_sha256 === null) throw new Error("Hub не подтвердил локальный путь.");
  } else if (value.config !== null || value.expected_state_sha256 !== null) {
    throw new Error("Hub вернул противоречивое состояние локального пути.");
  }
  return value;
}

function localWebPreviewReply(value, config, apply = false, source = null) {
  const keys = ["protocol", "ok", "config", "expected_state_sha256", "source_manifest_sha256",
    "changed", "url", "certificate_verified", ...(apply ? ["enabled"] : [])].sort().join(",");
  if (!value || Object.keys(value).sort().join(",") !== keys || value.protocol !== 1 ||
      value.ok !== true || !localWebEqual(value.config, config) ||
      !(value.expected_state_sha256 === null || PUBLIC_WEB_HASH.test(value.expected_state_sha256)) ||
      !PUBLIC_WEB_HASH.test(value.source_manifest_sha256) ||
      typeof value.changed !== "boolean" || value.url !== LOCAL_WEB_URL ||
      value.certificate_verified !== false ||
      (apply && (value.enabled !== true || value.expected_state_sha256 === null ||
        value.source_manifest_sha256 !== source)))
    throw new Error("Hub вернул неверный результат проверки локального пути.");
  return value;
}

function localWebDisableReply(value) {
  if (!value || Object.keys(value).sort().join(",") !==
      "changed,enabled,expected_state_sha256,ok,protocol" || value.protocol !== 1 ||
      value.ok !== true || value.enabled !== false || value.expected_state_sha256 !== null ||
      typeof value.changed !== "boolean")
    throw new Error("Hub не подтвердил отключение локальной настройки.");
  return value;
}

function localWebDraft() {
  return localWebConfig({ panel_path: $("localWebPath").value.trim(),
    root_behavior: $("localWebRoot").value });
}

function localWebFill(config) {
  $("localWebPath").value = config?.panel_path || PUBLIC_WEB_DEFAULT_PATH;
  $("localWebRoot").value = config?.root_behavior || "untouched";
}

function localWebLoopback() {
  try { return publicWebSameOrigin() && location.protocol === "http:" &&
    isLoopback(new URL(location.href)); }
  catch { return false; }
}

function localWebAllowed() {
  return Boolean(state.token && hubCanGlobalAdmin() && localWebLoopback() &&
    !localWebClient.publicActive);
}

function localWebMessage(value) {
  localWebClient.message = value;
  $("localWebMessage").textContent = value;
  $("localWebMessage").hidden = !value;
}

function localWebLink(element, path) {
  element.href = location.origin + path;
  element.textContent = location.origin + path;
}

function localWebRender() {
  const client = localWebClient;
  const admin = Boolean(state.token && hubCanGlobalAdmin());
  $("localWebPanel").hidden = !admin;
  if (!admin) return;
  const active = Boolean(client.status?.enabled);
  $("localWebBadge").textContent = client.publicActive ? "Управляет HTTPS" :
    !client.status ? "Проверяем" : active ? "Локальный путь задан" : "Обычный путь";
  $("localWebBadge").className = `status-badge${active && !client.publicActive ? "" : " waiting"}`;
  $("localWebCurrent").textContent = !publicWebSameOrigin()
    ? "Откройте панель самого Hub через защищённый адрес или SSH-туннель."
    : client.publicActive ? "Публичный HTTPS управляет и локальным маршрутом. Изменяйте путь в разделе «Доступ с телефона по HTTPS»."
      : !client.status ? "Проверяем локальный маршрут…" : active
        ? `Сохранено: ${client.status.config.panel_path} · ${LOCAL_WEB_ROOT_LABELS[client.status.config.root_behavior]}.`
        : `Управляемая локальная настройка не включена. Обычный путь: ${PUBLIC_WEB_DEFAULT_PATH}.`;
  $("localWebOwnership").textContent = client.publicActive
    ? "Локальное изменение недоступно, пока включён публичный HTTPS. Сначала измените публичную настройку."
    : "«Оставить / как сейчас» сохраняет базовое поведение локального Web (обычно панель на /). При переходе к публичному HTTPS отключите локальную настройку; путь и правило сохранятся как черновик.";
  const path = client.discoveryPath || client.status?.config?.panel_path || PUBLIC_WEB_DEFAULT_PATH;
  const link = $("localWebCurrentLink");
  link.hidden = !localWebLoopback();
  if (!link.hidden) localWebLink(link, path);
  const locked = !localWebAllowed() || !client.status || client.loading || client.previewing ||
    client.applying || client.checking || Boolean(client.pending);
  $("localWebPath").disabled = locked;
  $("localWebRoot").disabled = locked;
  $("localWebPreview").disabled = locked || client.conflict;
  $("localWebPreview").textContent = client.previewing ? "Проверяем…" : "Проверить путь";
  $("localWebReload").disabled = !publicWebSameOrigin() || client.loading || client.applying;
  $("localWebDisable").hidden = !active || client.publicActive || !localWebLoopback();
  $("localWebDisable").disabled = locked;
  $("localWebPreviewCard").hidden = !client.preview || Boolean(client.pending);
  if (client.preview && !client.pending) {
    $("localWebPreviewSummary").textContent =
      `${location.origin}${client.preview.config.panel_path} · ${LOCAL_WEB_ROOT_LABELS[client.preview.config.root_behavior]}.`;
    $("localWebApply").disabled = client.conflict || client.applying;
  }
  $("localWebRecovery").hidden = !client.pending;
  if (client.pending) {
    $("localWebRecoveryText").textContent = client.recoveryMessage || "Проверяем Hub после перезапуска Web.";
    localWebLink($("localWebRecoveryLink"), client.pending.action === "disable"
      ? PUBLIC_WEB_DEFAULT_PATH : client.pending.config.panel_path);
    $("localWebRetry").disabled = client.applying || client.checking;
    $("localWebRepeat").hidden = !client.repeatAllowed;
    $("localWebRepeat").disabled = client.applying || client.checking;
  }
  $("localWebMessage").textContent = client.message;
  $("localWebMessage").hidden = !client.message;
}

function localWebStored() {
  try {
    const raw = localStorage.getItem(LOCAL_WEB_KEY);
    if (!raw) return null;
    const value = JSON.parse(raw);
    if (!value || Object.keys(value).sort().join(",") !==
        "action,config,expected_state_sha256,hub_origin,request_id,source_manifest_sha256" ||
        value.hub_origin !== location.origin || !["apply", "disable"].includes(value.action) ||
        !PUBLIC_WEB_UUID.test(value.request_id) ||
        !(value.expected_state_sha256 === null || PUBLIC_WEB_HASH.test(value.expected_state_sha256))) return null;
    localWebConfig(value.config);
    if (value.action === "apply" ? !PUBLIC_WEB_HASH.test(value.source_manifest_sha256) :
        value.source_manifest_sha256 !== null) return null;
    return value;
  } catch { return null; }
}

function localWebSave(value) {
  try {
    const raw = JSON.stringify(value);
    localStorage.setItem(LOCAL_WEB_KEY, raw);
    return localStorage.getItem(LOCAL_WEB_KEY) === raw;
  } catch { return false; }
}

function localWebTransfer(config) {
  try {
    const raw = JSON.stringify({ hub_origin: location.origin, ...config });
    localStorage.setItem(PUBLIC_WEB_LOCAL_TRANSFER_KEY, raw);
    return localStorage.getItem(PUBLIC_WEB_LOCAL_TRANSFER_KEY) === raw;
  } catch { return false; }
}

function localWebClearPending() {
  const id = localWebClient.pending?.request_id;
  localWebClient.pending = null;
  localWebClient.repeatAllowed = false;
  localWebClient.recoveryMessage = "";
  const saved = localWebStored();
  if (!id || !saved || saved.request_id === id) {
    try { localStorage.removeItem(LOCAL_WEB_KEY); } catch { /* No secret is stored. */ }
  }
}

function localWebClearTimers() {
  if (localWebClient.timer !== null) clearTimeout(localWebClient.timer);
  if (localWebClient.discoveryTimer !== null) clearTimeout(localWebClient.discoveryTimer);
  localWebClient.timer = null;
  localWebClient.discoveryTimer = null;
}

function localWebReset() {
  localWebClearTimers();
  localWebClient.generation++;
  localWebClient.refreshSeq++;
  Object.assign(localWebClient, { status: null, preview: null, pending: null, publicActive: false,
    dirty: false, originalHash: null, conflict: false, loading: false, previewing: false,
    applying: false, applyConflict: false, checking: false, checks: 0,
    discoveryAttempts: 0, discoveryPath: null,
    message: "", recoveryMessage: "", repeatAllowed: false });
  clearError($("localWebError"));
  clearError($("localWebApplyError"));
  clearError($("localWebDisableError"));
  $("localWebApplyDialog").close?.();
  $("localWebDisableDialog").close?.();
  localWebRender();
}
globalThis.localWebReset = localWebReset;
globalThis.localWebApplying = () => localWebClient.applying;
globalThis.localWebMode = () => localWebClient.publicActive ? "public" :
  localWebClient.status?.enabled ? "local" : localWebClient.status ? "none" : "unknown";
globalThis.localWebAccessChanged = () => {
  if (!state.token || !hubCanGlobalAdmin()) localWebReset();
  else localWebRender();
};

// Discovery is public and intentionally sent without the bearer token. A 503
// means Hub has not loaded the route yet; only a legacy 404 permits fallback.
async function localWebDiscover() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(new URL("/api/v1/panel-location", location.origin), {
      method: "GET", credentials: "omit", cache: "no-store", signal: controller.signal,
    });
    if (response.status === 404) return { path: PUBLIC_WEB_DEFAULT_PATH, legacy: true };
    if (response.status === 503) return { path: null, pending: true };
    if (!response.ok) throw new Error("Путь панели пока недоступен.");
    const value = JSON.parse(await response.text());
    if (!value || Object.keys(value).join(",") !== "panel_path")
      throw new Error("Hub вернул неверный путь панели.");
    const config = localWebConfig({ panel_path: value.panel_path, root_behavior: "untouched" });
    return { path: config.panel_path, legacy: false };
  } finally { clearTimeout(timer); }
}

async function localWebDiscoverAndNavigate(expected, navigate = false) {
  const client = localWebClient;
  const generation = client.generation, token = state.token, base = state.base;
  try {
    const result = await localWebDiscover();
    if (generation !== client.generation || token !== state.token || base !== state.base) return;
    if (result.pending) {
      $("localWebDiscovery").textContent = "Hub ещё определяет путь панели. Повторяем проверку; старый путь не подставляется.";
      if (navigate) localWebScheduleDiscovery(expected);
      return;
    }
    client.discoveryPath = result.path;
    $("localWebDiscovery").textContent = `${result.legacy ? "Старый Hub: используем привычный путь" : "Hub объявляет путь"}: ${result.path}`;
    localWebRender();
    if (!navigate) return;
    if (result.path !== expected) {
      localWebMessage("Hub объявляет другой путь. Не перенаправляем браузер; проверьте состояние и обновите панель.");
      return;
    }
    const destination = location.origin + result.path;
    if (destination !== location.origin + location.pathname || location.search || location.hash)
      location.assign(destination);
    else localWebMessage("Путь уже открыт. Новое правило действует после перезапуска Web.");
  } catch {
    if (generation === client.generation && token === state.token && base === state.base) {
      $("localWebDiscovery").textContent = "Не удалось определить путь панели. Проверьте связь с Hub.";
      if (navigate) localWebScheduleDiscovery(expected);
    }
  }
}

function localWebScheduleDiscovery(expected) {
  if (localWebClient.discoveryTimer !== null) clearTimeout(localWebClient.discoveryTimer);
  if (++localWebClient.discoveryAttempts > 20) {
    $("localWebDiscovery").textContent = "Hub не подтвердил путь за время ожидания. Нажмите «Загрузить действующее» и проверьте адрес вручную.";
    return;
  }
  localWebClient.discoveryTimer = setTimeout(() => {
    localWebClient.discoveryTimer = null;
    void localWebDiscoverAndNavigate(expected, true);
  }, 3500);
  localWebClient.discoveryTimer?.unref?.();
}

function localWebResolved(status) {
  const client = localWebClient, pending = client.pending;
  if (!pending) return false;
  const applied = pending.action === "apply" && status.enabled &&
    localWebEqual(status.config, pending.config);
  const disabled = pending.action === "disable" && !status.enabled;
  if (applied || disabled) {
    localWebClearTimers();
    localWebClearPending();
    client.status = status;
    client.preview = null;
    client.dirty = false;
    client.conflict = false;
    if (disabled) {
      localWebFill(pending.config);
      publicWebFill(null);
      publicWebClient.dirty = true;
      publicWebRender();
    } else localWebFill(status.config);
    globalThis.publicWebRender?.();
    localWebMessage(disabled
      ? "Локальная настройка отключена. Путь и правило сохранены для HTTPS; переходим на привычный путь."
      : "Локальный путь подтверждён. Проверяем объявленный Hub адрес перед переходом.");
    client.discoveryAttempts = 0;
    localWebRender();
    void localWebDiscoverAndNavigate(disabled ? PUBLIC_WEB_DEFAULT_PATH : status.config.panel_path, true);
    return true;
  }
  if (status.expected_state_sha256 !== pending.expected_state_sha256 || client.applyConflict) {
    localWebClearTimers();
    localWebClearPending();
    client.status = status;
    client.preview = null;
    client.conflict = true;
    localWebMessage("Hub не подтвердил изменение. Загрузите действующий путь и повторите предпросмотр.");
    localWebRender();
    return true;
  }
  return false;
}

async function localWebRefresh({ replace = false } = {}) {
  const client = localWebClient;
  if (!state.token || !hubCanGlobalAdmin()) return;
  if (!publicWebSameOrigin()) { localWebRender(); return; }
  if (client.loading || client.previewing || client.applying || client.checking) return;
  const generation = client.generation, token = state.token, base = state.base;
  const seq = ++client.refreshSeq;
  client.loading = true;
  localWebRender();
  try {
    const [local, publicStatus] = await Promise.all([
      request("/api/v1/local-web", { timeoutMs: 85000 }),
      request("/api/v1/public-web", { timeoutMs: 85000 }),
    ]);
    const status = localWebStatusReply(local);
    const publicState = publicWebStatusReply(publicStatus);
    if (generation !== client.generation || seq !== client.refreshSeq ||
        token !== state.token || base !== state.base) return;
    client.publicActive = publicState.enabled;
    client.status = status;
    globalThis.publicWebRender?.();
    if (!client.pending) client.pending = localWebStored();
    let resolved = false;
    if (client.pending) {
      resolved = localWebResolved(status);
      if (!resolved) {
        client.recoveryMessage = "Hub отвечает, но прежний локальный путь ещё действует. Запрос может продолжаться; повтор с тем же ID безопасен.";
        client.repeatAllowed = true;
      }
    } else if (replace || !client.dirty) {
      client.dirty = false;
      client.conflict = false;
      client.preview = null;
      client.originalHash = status.expected_state_sha256;
      localWebFill(status.config);
      if (replace) { clearError($("localWebError")); localWebMessage("Действующий путь загружен."); }
    } else if (status.expected_state_sha256 !== client.originalHash) {
      client.conflict = true;
      client.preview = null;
      showError($("localWebError"), "Путь изменён в другой вкладке. Загрузите действующее значение и проверьте заново.");
    }
    if (!resolved) void localWebDiscoverAndNavigate(null, false);
  } catch (error) {
    if (generation === client.generation && seq === client.refreshSeq && token === state.token && base === state.base)
      showError($("localWebError"), error.status === 404
        ? "Обновите Hub для настройки локального пути." :
          error.message || "Не удалось прочитать локальную настройку.");
  } finally {
    if (generation === client.generation && seq === client.refreshSeq && token === state.token && base === state.base) {
      client.loading = false;
      localWebRender();
    }
  }
}
globalThis.localWebRefresh = localWebRefresh;

async function localWebPreview(event) {
  event?.preventDefault?.();
  const client = localWebClient;
  if (!localWebAllowed() || !client.status || client.pending || client.loading ||
      client.previewing || client.applying || client.conflict) return;
  let config;
  try { config = localWebDraft(); }
  catch (error) { showError($("localWebError"), error.message); return; }
  const generation = client.generation, token = state.token, base = state.base;
  client.preview = null;
  client.previewing = true;
  client.refreshSeq++;
  clearError($("localWebError"));
  localWebMessage("Проверяем локальный маршрут без изменения сервера.");
  localWebRender();
  try {
    const result = localWebPreviewReply(await request("/api/v1/local-web/preview", {
      method: "POST", body: JSON.stringify({ config }), timeoutMs: 130000,
    }), config);
    if (generation !== client.generation || token !== state.token || base !== state.base) return;
    if (!localWebEqual(localWebDraft(), config)) return;
    if (result.expected_state_sha256 !== client.status.expected_state_sha256) {
      client.conflict = true;
      throw new Error("Локальный путь изменился на сервере. Загрузите действующий и проверьте заново.");
    }
    client.preview = result;
    localWebMessage("Предпросмотр готов. Применение потребует отдельного подтверждения.");
  } catch (error) {
    if (generation === client.generation && token === state.token && base === state.base)
      showError($("localWebError"), error.status === 409
        ? "Публичный HTTPS активен или локальный путь изменился. Обновите состояние и используйте нужный раздел."
        : error.message || "Не удалось проверить локальный путь.");
  } finally {
    if (generation === client.generation && token === state.token && base === state.base) {
      client.previewing = false;
      localWebRender();
    }
  }
}

function localWebPrepareApply() {
  const client = localWebClient;
  if (!client.preview || client.pending || client.applying || client.conflict || !localWebAllowed()) return;
  let config;
  try { config = localWebDraft(); }
  catch (error) { showError($("localWebError"), error.message); return; }
  if (!localWebEqual(config, client.preview.config) ||
      client.preview.expected_state_sha256 !== client.status?.expected_state_sha256) {
    client.preview = null;
    showError($("localWebError"), "Поля или состояние изменились. Сделайте новый предпросмотр.");
    localWebRender();
    return;
  }
  $("localWebApplySummary").textContent =
    `${location.origin}${config.panel_path} · ${LOCAL_WEB_ROOT_LABELS[config.root_behavior]}.`;
  clearError($("localWebApplyError"));
  $("localWebApplyDialog").showModal();
}

function localWebPrepareDisable() {
  const client = localWebClient;
  if (!client.status?.enabled || client.pending || client.applying || !localWebAllowed()) return;
  $("localWebDisableSummary").textContent =
    `Сейчас: ${client.status.config.panel_path} · ${LOCAL_WEB_ROOT_LABELS[client.status.config.root_behavior]}.`;
  clearError($("localWebDisableError"));
  $("localWebDisableDialog").showModal();
}

async function localWebSend(pending) {
  const client = localWebClient;
  const generation = client.generation, token = state.token, base = state.base;
  client.applying = true;
  client.applyConflict = false;
  client.refreshSeq++;
  client.repeatAllowed = false;
  client.recoveryMessage = "Web может перезапуститься. Ждём подтверждения Hub…";
  localWebRender();
  try {
    const action = pending.action;
    const payload = action === "apply" ? { config: pending.config,
      expected_state_sha256: pending.expected_state_sha256,
      source_manifest_sha256: pending.source_manifest_sha256, request_id: pending.request_id } :
      { expected_state_sha256: pending.expected_state_sha256, request_id: pending.request_id };
    const result = await request(`/api/v1/local-web/${action}`, {
      method: "POST", body: JSON.stringify(payload), timeoutMs: 680000,
    });
    if (generation !== client.generation || token !== state.token || base !== state.base ||
        client.pending?.request_id !== pending.request_id) return;
    if (action === "apply") {
      localWebPreviewReply(result, pending.config, true, pending.source_manifest_sha256);
      client.status = { protocol: 1, ok: true, enabled: true, config: pending.config,
        expected_state_sha256: result.expected_state_sha256 };
    } else {
      localWebDisableReply(result);
      client.status = { protocol: 1, ok: true, enabled: false, config: null,
        expected_state_sha256: null };
    }
    localWebResolved(client.status);
  } catch (error) {
    if (generation === client.generation && token === state.token && base === state.base &&
        client.pending?.request_id === pending.request_id) {
      client.applyConflict = error.status === 409;
      client.recoveryMessage = "Ответ применения потерян или не окончателен. Проверяем состояние Hub; второй новый запрос не создаётся.";
      localWebScheduleRecovery(0);
    }
  } finally {
    if (generation === client.generation && token === state.token && base === state.base) {
      client.applying = false;
      localWebRender();
    }
  }
}

async function localWebStart(action) {
  const client = localWebClient;
  if (client.pending || client.applying || !localWebAllowed() || !client.status) return;
  let config;
  try { config = action === "apply" ? localWebDraft() : localWebConfig(client.status.config); }
  catch (error) { showError($(action === "apply" ? "localWebApplyError" : "localWebDisableError"), error.message); return; }
  if (action === "apply" && (!client.preview || !localWebEqual(config, client.preview.config) ||
      client.preview.expected_state_sha256 !== client.status.expected_state_sha256)) {
    showError($("localWebApplyError"), "Предпросмотр устарел. Проверьте путь заново."); return;
  }
  let requestId;
  try { requestId = crypto.randomUUID(); }
  catch { showError($(action === "apply" ? "localWebApplyError" : "localWebDisableError"),
    "Браузер не может создать защищённый ID запроса."); return; }
  const pending = { hub_origin: location.origin, action, request_id: requestId, config,
    expected_state_sha256: client.status.expected_state_sha256,
    source_manifest_sha256: action === "apply" ? client.preview.source_manifest_sha256 : null };
  if (action === "disable" && !localWebTransfer(config)) {
    showError($("localWebDisableError"), "Браузер не сохранил путь для перехода к HTTPS. Разрешите локальное хранилище.");
    return;
  }
  if (!localWebSave(pending)) {
    showError($(action === "apply" ? "localWebApplyError" : "localWebDisableError"),
      "Браузер не сохранил ID восстановления. Разрешите локальное хранилище.");
    return;
  }
  $(action === "apply" ? "localWebApplyDialog" : "localWebDisableDialog").close();
  client.pending = pending;
  client.preview = null;
  client.checks = 0;
  await localWebSend(pending);
}

function localWebScheduleRecovery(delay = 5000) {
  if (localWebClient.timer !== null) clearTimeout(localWebClient.timer);
  if (!localWebClient.pending || localWebClient.checks >= 12) return;
  localWebClient.timer = setTimeout(() => {
    localWebClient.timer = null;
    void localWebCheckRecovery();
  }, delay);
  localWebClient.timer?.unref?.();
}

async function localWebCheckRecovery() {
  const client = localWebClient;
  if (!client.pending || client.checking || client.applying || !state.token ||
      !hubCanGlobalAdmin() || !publicWebSameOrigin()) return;
  const generation = client.generation, token = state.token, base = state.base;
  client.checking = true;
  client.checks++;
  localWebRender();
  try {
    const status = localWebStatusReply(await request("/api/v1/local-web", { timeoutMs: 12000 }));
    if (generation !== client.generation || token !== state.token || base !== state.base) return;
    client.status = status;
    if (!localWebResolved(status)) {
      client.recoveryMessage = "Hub отвечает, но прежняя конфигурация ещё активна. Повтор с тем же ID не создаст вторую операцию.";
      client.repeatAllowed = true;
      localWebScheduleRecovery();
    }
  } catch {
    if (generation === client.generation && token === state.token && base === state.base) {
      client.recoveryMessage = "Hub пока не отвечает. ID запроса сохранён; проверьте позже. Через SSH доступен привычный путь /sovagrid/monitoring/.";
      client.repeatAllowed = false;
      localWebScheduleRecovery();
    }
  } finally {
    if (generation === client.generation && token === state.token && base === state.base) {
      client.checking = false;
      localWebRender();
    }
  }
}

$("localWebForm").addEventListener("submit", (event) => { void localWebPreview(event); });
$("localWebReload").addEventListener("click", () => { void localWebRefresh({ replace: true }); });
$("localWebApply").addEventListener("click", localWebPrepareApply);
$("localWebDisable").addEventListener("click", localWebPrepareDisable);
$("localWebApplyCancel").addEventListener("click", () => $("localWebApplyDialog").close());
$("localWebDisableCancel").addEventListener("click", () => $("localWebDisableDialog").close());
$("localWebApplyConfirm").addEventListener("click", () => { void localWebStart("apply"); });
$("localWebDisableConfirm").addEventListener("click", () => { void localWebStart("disable"); });
$("localWebRetry").addEventListener("click", () => { void localWebCheckRecovery(); });
$("localWebRepeat").addEventListener("click", () => {
  if (localWebClient.pending && localWebClient.repeatAllowed) void localWebSend(localWebClient.pending);
});
for (const id of ["localWebPath", "localWebRoot"]) $(id).addEventListener("input", () => {
  if (localWebClient.pending || localWebClient.applying) return;
  localWebClient.dirty = true;
  localWebClient.originalHash ??= localWebClient.status?.expected_state_sha256;
  localWebClient.preview = null;
  localWebMessage("");
  if (!localWebClient.conflict) clearError($("localWebError"));
  localWebRender();
});
localWebRender();

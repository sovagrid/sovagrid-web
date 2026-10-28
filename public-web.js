/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// The browser stores only public configuration and the idempotent request ID.
// Hub credentials remain in app.js memory and never enter a URL or storage.
const publicWebClient = { generation: 0, refreshSeq: 0, status: null, preview: null,
  pending: null, dirty: false, conflict: false, originalStateHash: null,
  loading: false, previewing: false,
  applying: false, applyConflict: false, checking: false, checks: 0, recoveryTimer: null,
  message: "", recoveryMessage: "", repeatAllowed: false };
const PUBLIC_WEB_KEY = "sovagrid.public-web.pending.v1";
const PUBLIC_WEB_LOCAL_TRANSFER_KEY = "sovagrid.public-web.local-route-transfer.v1";
const PUBLIC_WEB_DEFAULT_PATH = "/sovagrid/monitoring/";
const PUBLIC_WEB_HASH = /^[0-9a-f]{64}$/;
const PUBLIC_WEB_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PUBLIC_WEB_PATH = /^\/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\/){1,3}$/;
const PUBLIC_WEB_FIELDS = ["mode", "address", "acme_environment", "panel_path", "root_behavior"];
const PUBLIC_WEB_ROOT_LABELS = { untouched: "Не открывать панель на /", panel: "Открывать панель на /",
  redirect: "Перенаправлять / на путь панели", not_found: "Отвечать 404 на /" };

function publicWebSameOrigin() {
  try {
    const origin = new URL(state.base).origin;
    return origin === location.origin && state.base === origin &&
      (location.protocol === "https:" || (location.protocol === "http:" && isLoopback(new URL(location.href))));
  } catch { return false; }
}

function publicWebIPv4(value) {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) &&
    Number(part) <= 255 && String(Number(part)) === part);
}

function publicWebConfig(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).sort().join(",") !== [...PUBLIC_WEB_FIELDS].sort().join(","))
    throw new Error("Неверные настройки публичной панели.");
  const { mode, address, acme_environment: acme, panel_path: path, root_behavior: root } = value;
  if (!["ip", "dns"].includes(mode) || typeof address !== "string" || !address || address.length > 253 ||
      !["production", "staging"].includes(acme) || typeof path !== "string" || path.length > 96 ||
      !PUBLIC_WEB_PATH.test(path) || ["api", "healthz"].includes(path.split("/")[1]) ||
      !Object.hasOwn(PUBLIC_WEB_ROOT_LABELS, root))
    throw new Error("Проверьте публичный адрес, путь и поведение главной страницы.");
  if (mode === "ip" ? !publicWebIPv4(address) :
      !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]*$/.test(address) ||
        /\.(?:local|localhost|internal|test|invalid|example)$/.test(address))
    throw new Error(mode === "ip" ? "Укажите IPv4 без порта и лишних нулей." :
      "Укажите домен строчными латинскими буквами без схемы, порта и пути.");
  return { mode, address, acme_environment: acme, panel_path: path, root_behavior: root };
}

function publicWebEqual(a, b) {
  return Boolean(a && b && PUBLIC_WEB_FIELDS.every((field) => a[field] === b[field]));
}

function publicWebStatusReply(value) {
  if (!value || Object.keys(value).sort().join(",") !==
      "config,enabled,expected_state_sha256,ok,protocol" || value.protocol !== 1 || value.ok !== true ||
      typeof value.enabled !== "boolean" ||
      !(value.expected_state_sha256 === null || PUBLIC_WEB_HASH.test(value.expected_state_sha256)))
    throw new Error("Hub вернул неверное состояние публичной панели.");
  if (value.enabled) {
    publicWebConfig(value.config);
    if (value.expected_state_sha256 === null) throw new Error("Hub не подтвердил состояние публичной панели.");
  } else if (value.config !== null || value.expected_state_sha256 !== null) {
    throw new Error("Hub вернул противоречивое состояние публичной панели.");
  }
  return value;
}

function publicWebPreviewReply(value, config, apply = false, source = null) {
  const names = ["protocol", "ok", "config", "expected_state_sha256", "source_manifest_sha256",
    "changed", "url", "certificate_verified", ...(apply ? ["enabled"] : [])].sort().join(",");
  if (!value || Object.keys(value).sort().join(",") !== names || value.protocol !== 1 || value.ok !== true ||
      !publicWebEqual(value.config, config) ||
      !(value.expected_state_sha256 === null || PUBLIC_WEB_HASH.test(value.expected_state_sha256)) ||
      !PUBLIC_WEB_HASH.test(value.source_manifest_sha256) || typeof value.changed !== "boolean" ||
      value.url !== `https://${config.address}` || typeof value.certificate_verified !== "boolean" ||
      (apply ? (value.enabled !== true || value.expected_state_sha256 === null ||
        value.source_manifest_sha256 !== source ||
        value.certificate_verified !== (config.acme_environment === "production")) :
        value.certificate_verified !== false))
    throw new Error("Hub вернул неверный результат проверки адреса.");
  return value;
}

function publicWebDraft() {
  return publicWebConfig({ mode: $("publicWebMode").value,
    address: $("publicWebAddress").value.trim(), acme_environment: $("publicWebAcme").value,
    panel_path: $("publicWebPath").value.trim(), root_behavior: $("publicWebRoot").value });
}

function publicWebDefault() {
  const host = location.hostname;
  const mode = publicWebIPv4(host) ? "ip" : "dns";
  let address = "";
  try { if (!isLoopback(new URL(location.href))) address = publicWebConfig({ mode, address: host,
    acme_environment: "production", panel_path: PUBLIC_WEB_DEFAULT_PATH,
    root_behavior: "untouched" }).address; }
  catch { /* Local loopback does not reveal the server's public address. */ }
  let panelPath = PUBLIC_WEB_DEFAULT_PATH, rootBehavior = "untouched";
  try {
    const transfer = JSON.parse(localStorage.getItem(PUBLIC_WEB_LOCAL_TRANSFER_KEY) || "null");
    if (transfer?.hub_origin === location.origin &&
        Object.keys(transfer).sort().join(",") === "hub_origin,panel_path,root_behavior" &&
        typeof transfer.panel_path === "string" && transfer.panel_path.length <= 96 &&
        PUBLIC_WEB_PATH.test(transfer.panel_path) &&
        !["api", "healthz"].includes(transfer.panel_path.split("/")[1]) &&
        Object.hasOwn(PUBLIC_WEB_ROOT_LABELS, transfer.root_behavior)) {
      panelPath = transfer.panel_path;
      rootBehavior = transfer.root_behavior;
    }
  } catch { /* Local storage is optional for read-only defaults. */ }
  return { mode: address ? mode : "ip", address, acme_environment: "production",
    panel_path: panelPath, root_behavior: rootBehavior };
}

function publicWebFill(config) {
  const value = config || publicWebDefault();
  $("publicWebMode").value = value.mode;
  $("publicWebAddress").value = value.address;
  $("publicWebAcme").value = value.acme_environment;
  $("publicWebPath").value = value.panel_path;
  $("publicWebRoot").value = value.root_behavior;
}

function publicWebUrl(config) { return `https://${config.address}${config.panel_path}`; }

function publicWebLink(element, config) {
  const url = publicWebUrl(config);
  element.href = url;
  element.textContent = url;
}

function publicWebSetMessage(message) {
  publicWebClient.message = message;
  $("publicWebMessage").textContent = message;
  $("publicWebMessage").hidden = !message;
}

function publicWebRender() {
  const client = publicWebClient;
  const admin = Boolean(state.token && hubCanGlobalAdmin());
  $("publicWebPanel").hidden = !admin;
  if (!admin) return;
  const available = publicWebSameOrigin();
  const active = Boolean(client.status?.enabled);
  const localActive = globalThis.localWebMode?.() === "local";
  $("publicWebBadge").textContent = !available ? "Нужен адрес этого Hub" :
    localActive ? "Сначала локальный режим" : !client.status ? "Проверяем" :
      active ? "HTTPS включён" : "Не включён";
  $("publicWebBadge").className = `status-badge${active && available ? "" : " waiting"}`;
  $("publicWebCurrent").textContent = !available
    ? "Откройте панель на HTTPS-адресе этого Hub или через его локальный SSH-туннель."
    : !client.status ? "Проверяем действующий адрес…" : !active
      ? "Публичный HTTPS ещё не включён. Настройка ниже не затрагивает локальный SSH-туннель."
      : `Сейчас: ${publicWebUrl(client.status.config)} · ${PUBLIC_WEB_ROOT_LABELS[client.status.config.root_behavior]}.`;
  const currentLink = $("publicWebCurrentLink");
  currentLink.hidden = !active;
  if (active) publicWebLink(currentLink, client.status.config);
  const locked = !available || !client.status || client.loading || client.previewing ||
    client.applying || client.checking || Boolean(client.pending);
  for (const id of ["publicWebMode", "publicWebAddress", "publicWebPath", "publicWebRoot", "publicWebAcme"])
    $(id).disabled = locked;
  $("publicWebPreview").disabled = locked || client.conflict || localActive;
  $("publicWebPreview").textContent = client.previewing ? "Проверяем…" : "Проверить настройки";
  $("publicWebReload").disabled = !available || client.loading || client.previewing || client.applying;
  $("publicWebPreviewCard").hidden = !client.preview || Boolean(client.pending);
  if (client.preview && !client.pending) {
    const config = client.preview.config;
    $("publicWebPreviewSummary").textContent = `${publicWebUrl(config)} · ${config.mode === "ip" ? "публичный IP" : "домен"}.`;
    $("publicWebPreviewRoot").textContent = `Корень /: ${PUBLIC_WEB_ROOT_LABELS[config.root_behavior]}.`;
    $("publicWebPreviewNotice").textContent = config.acme_environment === "staging"
      ? "Тестовому сертификату телефоны и браузеры не доверяют. Переход будет ручным."
      : "Предпросмотр не меняет сервер. Настоящий сертификат будет проверен при применении.";
    $("publicWebApply").disabled = client.conflict || client.applying;
  }
  $("publicWebRecovery").hidden = !client.pending;
  if (client.pending) {
    $("publicWebRecoveryText").textContent = client.recoveryMessage ||
      "Запрос отправлен. Проверяем состояние после перезапуска Web.";
    publicWebLink($("publicWebRecoveryLink"), client.pending.config);
    $("publicWebRetry").disabled = client.applying || client.checking;
    $("publicWebRepeat").hidden = !client.repeatAllowed;
    $("publicWebRepeat").disabled = client.applying || client.checking;
  }
  $("publicWebMessage").textContent = client.message;
  $("publicWebMessage").hidden = !client.message;
}

function publicWebStorageRead() {
  try {
    const raw = localStorage.getItem(PUBLIC_WEB_KEY);
    if (!raw) return null;
    const value = JSON.parse(raw);
    if (!value || Object.keys(value).sort().join(",") !==
        "config,expected_state_sha256,hub_origin,request_id,source_manifest_sha256" ||
        value.hub_origin !== location.origin || !PUBLIC_WEB_UUID.test(value.request_id) ||
        !(value.expected_state_sha256 === null || PUBLIC_WEB_HASH.test(value.expected_state_sha256)) ||
        !PUBLIC_WEB_HASH.test(value.source_manifest_sha256)) return null;
    publicWebConfig(value.config);
    return value;
  } catch { return null; }
}

function publicWebStorageWrite(value) {
  try {
    localStorage.setItem(PUBLIC_WEB_KEY, JSON.stringify(value));
    return localStorage.getItem(PUBLIC_WEB_KEY) === JSON.stringify(value);
  } catch { return false; }
}

function publicWebClearPending() {
  const id = publicWebClient.pending?.request_id;
  publicWebClient.pending = null;
  publicWebClient.repeatAllowed = false;
  publicWebClient.recoveryMessage = "";
  const saved = publicWebStorageRead();
  if (!id || !saved || saved.request_id === id) {
    try { localStorage.removeItem(PUBLIC_WEB_KEY); } catch { /* Current tab still holds no token in storage. */ }
  }
}

function publicWebCancelRecoveryTimer() {
  if (publicWebClient.recoveryTimer !== null) clearTimeout(publicWebClient.recoveryTimer);
  publicWebClient.recoveryTimer = null;
}

function publicWebReset() {
  publicWebCancelRecoveryTimer();
  publicWebClient.generation++;
  publicWebClient.refreshSeq++;
  Object.assign(publicWebClient, { status: null, preview: null, pending: null, dirty: false,
    conflict: false, originalStateHash: null, loading: false, previewing: false,
    applying: false, applyConflict: false, checking: false,
    checks: 0, message: "", recoveryMessage: "", repeatAllowed: false });
  clearError($("publicWebError"));
  clearError($("publicWebApplyError"));
  $("publicWebApplyDialog").close?.();
  publicWebRender();
}
globalThis.publicWebReset = publicWebReset;
globalThis.publicWebApplying = () => publicWebClient.applying;
globalThis.publicWebAccessChanged = () => {
  if (!state.token || !hubCanGlobalAdmin()) publicWebReset();
  else publicWebRender();
};

function publicWebNavigate(config) {
  const publicOrigin = `https://${config.address}`;
  const current = new URL(location.href);
  const destination = isLoopback(current) ? location.origin + config.panel_path :
    publicOrigin + config.panel_path;
  if (config.acme_environment === "staging" && new URL(destination).origin !== location.origin) {
    publicWebSetMessage(`Настройка применена. Тестовому сертификату браузер не доверяет; откройте ${publicWebUrl(config)} вручную.`);
    return;
  }
  if (destination !== current.origin + current.pathname || current.search || current.hash) {
    // A full navigation re-registers the service worker under the new scope.
    // No bearer, SSH grant or recovery ID is ever appended to the address.
    location.assign(destination);
  } else {
    publicWebSetMessage("Настройка применена. Адрес панели уже открыт; новые правила действуют.");
  }
}

function publicWebResolved(status) {
  const pending = publicWebClient.pending;
  if (!pending) return false;
  if (status.enabled && publicWebEqual(status.config, pending.config)) {
    publicWebCancelRecoveryTimer();
    publicWebClearPending();
    publicWebClient.status = status;
    publicWebClient.preview = null;
    publicWebClient.dirty = false;
    publicWebClient.conflict = false;
    publicWebFill(status.config);
    publicWebSetMessage("Настройка подтверждена Hub. Переходим на выбранный путь; потребуется повторный вход.");
    publicWebRender();
    publicWebNavigate(status.config);
    return true;
  }
  if (status.expected_state_sha256 !== pending.expected_state_sha256) {
    publicWebCancelRecoveryTimer();
    publicWebClearPending();
    publicWebClient.status = status;
    publicWebClient.preview = null;
    publicWebClient.dirty = false;
    publicWebClient.conflict = false;
    publicWebFill(status.config);
    publicWebSetMessage("На Hub теперь другая конфигурация. Проверьте её и создайте новый предпросмотр.");
    publicWebRender();
    return true;
  }
  if (publicWebClient.applyConflict) {
    publicWebCancelRecoveryTimer();
    publicWebClearPending();
    publicWebClient.applyConflict = false;
    publicWebClient.preview = null;
    publicWebClient.conflict = true;
    publicWebSetMessage("Hub не применил изменение. Загрузите действующие настройки и выполните новый предпросмотр.");
    publicWebRender();
    return true;
  }
  return false;
}

async function publicWebRefresh({ replace = false } = {}) {
  if (!state.token || !hubCanGlobalAdmin()) return;
  if (!publicWebSameOrigin()) { publicWebRender(); return; }
  if (publicWebClient.loading || publicWebClient.applying || publicWebClient.previewing || publicWebClient.checking) return;
  const client = publicWebClient;
  const generation = client.generation, token = state.token, base = state.base;
  const seq = ++client.refreshSeq;
  client.loading = true;
  publicWebRender();
  try {
    const status = publicWebStatusReply(await request("/api/v1/public-web", { timeoutMs: 85000 }));
    if (generation !== client.generation || seq !== client.refreshSeq || token !== state.token || base !== state.base) return;
    if (!client.pending) client.pending = publicWebStorageRead();
    client.status = status;
    if (client.pending) {
      if (!publicWebResolved(status)) {
        client.recoveryMessage = "Hub доступен, но выбранная настройка пока не подтверждена. Запрос может ещё выполняться. Проверяйте состояние или повторите его с тем же ID.";
        client.repeatAllowed = true;
      }
    } else if (replace || !client.dirty) {
      client.dirty = false;
      client.conflict = false;
      client.preview = null;
      client.originalStateHash = status.expected_state_sha256;
      publicWebFill(status.config);
      if (replace) { clearError($("publicWebError")); publicWebSetMessage("Действующие настройки загружены."); }
    } else if (status.expected_state_sha256 !== client.preview?.expected_state_sha256 &&
               status.expected_state_sha256 !== client.originalStateHash) {
      client.conflict = true;
      client.preview = null;
      showError($("publicWebError"), "Адрес изменён в другой вкладке. Загрузите действующие настройки и проверьте их заново.");
    }
  } catch (error) {
    if (generation === client.generation && seq === client.refreshSeq && token === state.token && base === state.base) {
      showError($("publicWebError"), error.status === 404
        ? "Обновите Hub, чтобы настраивать адрес панели здесь." :
          error.message || "Не удалось прочитать настройки публичной панели.");
    }
  } finally {
    if (generation === client.generation && seq === client.refreshSeq && token === state.token && base === state.base) {
      client.loading = false;
      publicWebRender();
    }
  }
}
globalThis.publicWebRefresh = publicWebRefresh;

async function publicWebPreview(event) {
  event?.preventDefault?.();
  const client = publicWebClient;
  if (!state.token || !hubCanGlobalAdmin() || !publicWebSameOrigin() || !client.status ||
      client.pending || client.loading || client.previewing || client.applying || client.conflict) return;
  if (globalThis.localWebMode?.() === "local") {
    showError($("publicWebError"), "Сначала отключите локальную настройку пути выше. Её путь и правило сохранятся для HTTPS.");
    return;
  }
  let config;
  try { config = publicWebDraft(); }
  catch (error) { showError($("publicWebError"), error.message); return; }
  const generation = client.generation, token = state.token, base = state.base;
  client.preview = null;
  client.previewing = true;
  client.refreshSeq++;
  clearError($("publicWebError"));
  publicWebSetMessage("Проверяем конфигурацию на сервере. Публичный адрес пока не меняется.");
  publicWebRender();
  try {
    const result = publicWebPreviewReply(await request("/api/v1/public-web/preview", {
      method: "POST", body: JSON.stringify({ config }), timeoutMs: 130000,
    }), config);
    if (generation !== client.generation || token !== state.token || base !== state.base) return;
    if (!publicWebEqual(publicWebDraft(), config)) return;
    if (result.expected_state_sha256 !== client.status.expected_state_sha256) {
      client.conflict = true;
      throw new Error("Настройка изменилась на сервере. Загрузите действующие значения и проверьте их заново.");
    }
    client.preview = result;
    publicWebSetMessage(result.changed ? "Предпросмотр готов. Для изменения подтвердите применение." :
      "Эта настройка уже выбрана. Применение повторно проверит работающий адрес.");
  } catch (error) {
    if (generation === client.generation && token === state.token && base === state.base)
      showError($("publicWebError"), error.status === 409 &&
        /Local-only panel is active/.test(error.message || "") ?
        "Сначала отключите локальную настройку пути выше, затем заново проверьте публичный HTTPS-адрес." :
        error.status === 409 ? "Состояние изменилось. Загрузите действующие настройки и повторите проверку." :
        error.message || "Предпросмотр не удался.");
  } finally {
    if (generation === client.generation && token === state.token && base === state.base) {
      client.previewing = false;
      publicWebRender();
    }
  }
}

function publicWebPrepareApply() {
  const client = publicWebClient;
  if (!client.preview || client.pending || client.applying || client.conflict ||
      !state.token || !hubCanGlobalAdmin() || !publicWebSameOrigin()) return;
  let config;
  try { config = publicWebDraft(); }
  catch (error) { showError($("publicWebError"), error.message); return; }
  if (!publicWebEqual(config, client.preview.config) ||
      client.preview.expected_state_sha256 !== client.status?.expected_state_sha256) {
    client.preview = null;
    showError($("publicWebError"), "Поля или состояние изменились. Сделайте новый предпросмотр.");
    publicWebRender();
    return;
  }
  $("publicWebApplySummary").textContent = `${publicWebUrl(config)} · ${PUBLIC_WEB_ROOT_LABELS[config.root_behavior]}.`;
  clearError($("publicWebApplyError"));
  $("publicWebApplyDialog").showModal();
}

async function publicWebSendApply(pending) {
  const client = publicWebClient;
  const generation = client.generation, token = state.token, base = state.base;
  client.applying = true;
  client.applyConflict = false;
  client.refreshSeq++;
  client.repeatAllowed = false;
  client.recoveryMessage = "Web может перезапуститься. Ждём подтверждения Hub…";
  publicWebRender();
  try {
    const result = publicWebPreviewReply(await request("/api/v1/public-web/apply", {
      method: "POST", body: JSON.stringify({ config: pending.config,
        expected_state_sha256: pending.expected_state_sha256,
        source_manifest_sha256: pending.source_manifest_sha256, request_id: pending.request_id }),
      timeoutMs: 680000,
    }), pending.config, true, pending.source_manifest_sha256);
    if (generation !== client.generation || token !== state.token || base !== state.base ||
        client.pending?.request_id !== pending.request_id) return;
    if (result.expected_state_sha256 === pending.expected_state_sha256 && result.changed)
      throw new Error("Hub не подтвердил новую конфигурацию.");
    client.status = { protocol: 1, ok: true, enabled: true, config: pending.config,
      expected_state_sha256: result.expected_state_sha256 };
    client.applyConflict = false;
    publicWebCancelRecoveryTimer();
    publicWebClearPending();
    client.preview = null;
    client.dirty = false;
    client.conflict = false;
    publicWebFill(pending.config);
    publicWebSetMessage("Публичный адрес проверен. Переходим к выбранному пути; потребуется повторный вход.");
    publicWebRender();
    publicWebNavigate(pending.config);
  } catch (error) {
    if (generation === client.generation && token === state.token && base === state.base &&
        client.pending?.request_id === pending.request_id) {
      client.applyConflict = error.status === 409;
      client.recoveryMessage = "Ответ применения не получен или не окончателен. Проверяем состояние Hub; второй новый запрос не создаётся.";
      publicWebSetMessage(error.status === 409
        ? "Hub отклонил изменение. Сверяем действующую конфигурацию перед дальнейшими действиями."
        : "Связь с Web могла прерваться из-за перезапуска. Сверяем действующую конфигурацию.");
      publicWebScheduleRecovery(0);
    }
  } finally {
    if (generation === client.generation && token === state.token && base === state.base) {
      client.applying = false;
      publicWebRender();
    }
  }
}

async function publicWebApply() {
  const client = publicWebClient;
  if (!client.preview) {
    showError($("publicWebApplyError"), "Предпросмотр устарел. Закройте окно и проверьте настройки заново.");
    return;
  }
  if (client.pending || client.applying || !state.token || !hubCanGlobalAdmin() || !publicWebSameOrigin()) return;
  let config;
  try { config = publicWebDraft(); }
  catch (error) { showError($("publicWebApplyError"), error.message); return; }
  if (!publicWebEqual(config, client.preview.config) ||
      client.preview.expected_state_sha256 !== client.status?.expected_state_sha256) {
    showError($("publicWebApplyError"), "Поля или состояние изменились. Закройте окно и сделайте новый предпросмотр.");
    return;
  }
  let requestId;
  try { requestId = crypto.randomUUID(); }
  catch { showError($("publicWebApplyError"), "На этом адресе браузер не может создать защищённый ID запроса."); return; }
  const pending = { hub_origin: location.origin, request_id: requestId, config,
    expected_state_sha256: client.preview.expected_state_sha256,
    source_manifest_sha256: client.preview.source_manifest_sha256 };
  if (!publicWebStorageWrite(pending)) {
    showError($("publicWebApplyError"), "Браузер не сохранил ID восстановления. Разрешите локальное хранилище и повторите.");
    return;
  }
  $("publicWebApplyDialog").close();
  client.pending = pending;
  client.preview = null;
  client.checks = 0;
  await publicWebSendApply(pending);
}

function publicWebScheduleRecovery(delay = 5000) {
  publicWebCancelRecoveryTimer();
  if (!publicWebClient.pending || publicWebClient.checks >= 12) return;
  publicWebClient.recoveryTimer = setTimeout(() => {
    publicWebClient.recoveryTimer = null;
    void publicWebCheckRecovery();
  }, delay);
  publicWebClient.recoveryTimer?.unref?.();
}

async function publicWebCheckRecovery() {
  const client = publicWebClient;
  if (!client.pending || client.checking || client.applying || !state.token ||
      !hubCanGlobalAdmin() || !publicWebSameOrigin()) return;
  const generation = client.generation, token = state.token, base = state.base;
  client.checking = true;
  client.checks++;
  publicWebRender();
  try {
    const status = publicWebStatusReply(await request("/api/v1/public-web", { timeoutMs: 12000 }));
    if (generation !== client.generation || token !== state.token || base !== state.base) return;
    client.status = status;
    if (!publicWebResolved(status)) {
      client.recoveryMessage = "Hub отвечает, но прежняя конфигурация ещё активна. Изменение может выполняться; повтор с тем же ID не создаст вторую операцию.";
      client.repeatAllowed = true;
      publicWebScheduleRecovery();
    }
  } catch {
    if (generation === client.generation && token === state.token && base === state.base) {
      client.recoveryMessage = "Hub пока не отвечает. ID запроса сохранён. Проверьте позже или откройте предложенный HTTPS-адрес и войдите там заново.";
      client.repeatAllowed = false;
      publicWebScheduleRecovery();
    }
  } finally {
    if (generation === client.generation && token === state.token && base === state.base) {
      client.checking = false;
      publicWebRender();
    }
  }
}

$("publicWebForm").addEventListener("submit", (event) => { void publicWebPreview(event); });
$("publicWebReload").addEventListener("click", () => { void publicWebRefresh({ replace: true }); });
$("publicWebApply").addEventListener("click", publicWebPrepareApply);
$("publicWebApplyCancel").addEventListener("click", () => $("publicWebApplyDialog").close());
$("publicWebApplyConfirm").addEventListener("click", () => { void publicWebApply(); });
$("publicWebRetry").addEventListener("click", () => { void publicWebCheckRecovery(); });
$("publicWebRepeat").addEventListener("click", () => {
  if (publicWebClient.pending && publicWebClient.repeatAllowed) void publicWebSendApply(publicWebClient.pending);
});
for (const id of ["publicWebMode", "publicWebAddress", "publicWebPath", "publicWebRoot", "publicWebAcme"])
  $(id).addEventListener("input", () => {
    if (publicWebClient.pending || publicWebClient.applying) return;
    publicWebClient.dirty = true;
    publicWebClient.originalStateHash ??= publicWebClient.status?.expected_state_sha256;
    publicWebClient.preview = null;
    publicWebSetMessage("");
    if (!publicWebClient.conflict) clearError($("publicWebError"));
    publicWebRender();
  });
publicWebRender();
globalThis.publicWebRender = publicWebRender;

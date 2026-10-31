/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// Connect puts only its local one-use broker port in the fragment. Remove it
// before any asynchronous work; the actual SSH grant never enters a URL.
function takeSSHBootstrapPort() {
  const prefix = "#sg-bootstrap=";
  if (!location.hash?.startsWith(prefix)) return null;
  const raw = location.hash.slice(prefix.length);
  globalThis.history?.replaceState?.(globalThis.history.state, "", location.pathname + location.search);
  if (location.protocol !== "http:" || location.hostname !== "127.0.0.1" ||
      !/^[1-9][0-9]{0,4}$/.test(raw)) return null;
  const port = Number(raw);
  return port <= 65535 ? port : null;
}
const sshBootstrapPort = takeSSHBootstrapPort();
let browserSSHLanding = null;

const $ = (id) => document.getElementById(id);
const VPN_HUB_HOST = "@hub-host";
const state = { base: "", token: "", servers: [], incidents: [], jobs: [], audit: [], vpn: null, vpnInventoryTargetId: null, selectedId: null, view: "overview", firstLoad: true, startTelegram: null, startTelegramLoading: false, pendingCommand: "", pendingServerId: null, pendingCommandKey: null, submittingCommandKey: null, commandSubmitting: false, vpnTargetId: null, vpnPending: null, vpnSubmittingKey: null, vpnActionJobId: null, vpnActionJob: null, timer: null, refreshSeq: 0, passwordChangeSeq: 0, passwordChanging: false, history: [], chartField: "cpu_percent" };
state.user = null;
// No logged-in user is the trusted local test/CLI case. A real new session
// starts with unknown access and stays read-only until /session/access loads.
state.access = { mode: "all", revision: 0, unrestricted_admin: true };
const GLOBAL_ADMIN_VIEWS = new Set(["start", "telegram"]);
const SERVER_ADMIN_VIEWS = new Set(["commands", "journal", "files"]);
const ADMIN_AUDIT_VIEWS = new Set(["audit"]);
const ROLE_RANK = { viewer: 1, operator: 2, admin: 3 };
function hubSessionAccess(payload) {
  const access = payload?.access;
  if (!access || !["all", "selected"].includes(access.mode) ||
      !Number.isSafeInteger(access.revision) || access.revision < 0 ||
      typeof access.unrestricted_admin !== "boolean" ||
      (access.mode === "selected" && access.unrestricted_admin)) {
    throw new Error("Центр мониторинга вернул неверные права доступа к серверам.");
  }
  return { mode: access.mode, revision: access.revision,
    unrestricted_admin: access.unrestricted_admin };
}
async function hubLoadSessionAccess(user) {
  if (user.legacy) return { mode: "all", revision: 0, unrestricted_admin: true };
  try { return hubSessionAccess(await request("/api/v1/session/access")); }
  catch (error) {
    // Earlier Hub versions route unknown GETs through the admin gate. They
    // return 403 to viewers/operators and 404 to administrators.
    const oldRoleGate = error.status === 403 && error.message === "Insufficient role" &&
      ["viewer", "operator"].includes(user.role);
    if (error.status === 404 || oldRoleGate) return { mode: "all", revision: 0,
      unrestricted_admin: user.role === "admin" };
    throw error;
  }
}
function hubCanGlobalAdmin() {
  return !state.user || (state.user.role === "admin" && state.access?.unrestricted_admin === true);
}
function hubCanAudit() { return !state.user || (state.user.role === "admin" && Boolean(state.access)); }
function hubServerRole(server = selectedServer()) {
  if (!state.user) return "admin";
  if (!state.access) return null;
  if (!server) return null;
  const reported = server.access_role;
  if (Object.hasOwn(ROLE_RANK, reported)) {
    return ROLE_RANK[reported] <= ROLE_RANK[state.user.role] ? reported : state.user.role;
  }
  // Old Hub summaries have no access_role and always use the global role.
  return state.access?.mode === "all" ? state.user.role : null;
}
function hubCanAdmin(server = selectedServer()) { return hubServerRole(server) === "admin"; }
function hubCanAcknowledge(server = selectedServer()) { return ROLE_RANK[hubServerRole(server)] >= ROLE_RANK.operator; }
globalThis.hubCanAdmin = hubCanAdmin;
globalThis.hubCanAcknowledge = hubCanAcknowledge;
globalThis.hubCanGlobalAdmin = hubCanGlobalAdmin;

function hubSessionUser(payload, legacyUsername = "admin") {
  // Earlier Hub versions have one administrator and omit identity entirely.
  if (!Object.hasOwn(payload, "user")) return { id: null, username: legacyUsername, role: "admin", legacy: true };
  const user = payload.user;
  if (!user || typeof user.id !== "string" || !user.id || user.id.length > 64 ||
      typeof user.username !== "string" || !user.username || [...user.username].length > 80 ||
      !["viewer", "operator", "admin"].includes(user.role) || user.enabled !== true) {
    throw new Error("Центр мониторинга вернул неверные права доступа.");
  }
  return { id: user.id, username: user.username, role: user.role, legacy: false };
}

function applyHubPermissions() {
  const admin = hubCanAdmin(), globalAdmin = hubCanGlobalAdmin();
  if (!globalAdmin) globalThis.vpnJumpReset?.();
  for (const element of document.querySelectorAll("[data-admin-only], [data-command]")) element.hidden = !admin;
  for (const element of document.querySelectorAll("[data-vpn-admin-only]")) element.hidden = !vpnTarget() || !hubCanAdmin(vpnTarget());
  for (const element of document.querySelectorAll("[data-global-admin-only]")) element.hidden = !globalAdmin;
  for (const button of document.querySelectorAll("[data-view]")) {
    if (SERVER_ADMIN_VIEWS.has(button.dataset.view)) button.hidden = !admin;
    if (GLOBAL_ADMIN_VIEWS.has(button.dataset.view)) button.hidden = !globalAdmin;
    if (ADMIN_AUDIT_VIEWS.has(button.dataset.view)) button.hidden = !hubCanAudit();
  }
  if ((!admin && SERVER_ADMIN_VIEWS.has(state.view)) ||
      (!globalAdmin && GLOBAL_ADMIN_VIEWS.has(state.view)) ||
      (!hubCanAudit() && ADMIN_AUDIT_VIEWS.has(state.view))) state.view = "overview";
  const label = $("sessionIdentity");
  if (label) {
    const roles = { viewer: "Наблюдатель", operator: "Оператор", admin: "Администратор" };
    label.textContent = state.user ? `${state.user.username} · ${roles[state.user.role]}` : "";
  }
  const notice = $("accessNotice");
  if (notice) {
    notice.hidden = globalAdmin;
    notice.textContent = state.access?.mode === "selected"
      ? `Доступ ограничен выбранными серверами. Для этого сервера: ${hubServerRole() === "admin" ? "управление" : hubServerRole() === "operator" ? "мониторинг и подтверждение событий" : "просмотр"}.`
      : state.user?.role === "operator"
        ? "Режим оператора: мониторинг и подтверждение событий. Управление сервером доступно администратору."
        : "Режим наблюдателя: мониторинг и события. Изменения доступны оператору или администратору.";
  }
  globalThis.containerLogsAccessChanged?.();
  globalThis.containerActionAccessChanged?.();
  globalThis.publicWebAccessChanged?.();
  globalThis.localWebAccessChanged?.();
}
const SEALED_PROFILE_INFO = "SovaGrid sealed WireGuard profile v1";
let sealedPrepareSeq = 0;
let pendingSealedExport = null;
let activeSealedExport = null;
const sealedDownloadUrls = new Set();
// Hub permits four active terminal sessions globally and one per server.
const TERMINAL_TAB_LIMIT = 4;
function newTerminalClient(id, targetServerId = null) {
  return { id, targetServerId, token: "", base: "", serverId: null, sessionId: null, status: "idle", reason: "", error: "",
    pendingStart: null, pendingSince: null, startInFlight: false, after: 0, nextSeq: 1, operations: [], sending: null,
    inputBuffer: "", inputTimer: null, pollAbort: null, pollGeneration: 0,
    term: null, fit: null, screen: null, resizeObserver: null, resizeTimer: null, cols: 80, rows: 24 };
}
const terminalTabs = { items: [], nextId: 1 };
let terminalClient = newTerminalClient(terminalTabs.nextId++);
terminalTabs.items.push(terminalClient);
const number = (value) => value === null || value === undefined || value === "" ? null : Number.isFinite(Number(value)) ? Number(value) : null;
const clamp = (value) => Math.min(100, Math.max(0, number(value) ?? 0));

function apiBase(raw) {
  const url = new URL(raw);
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(loopback && url.protocol === "http:")) {
    throw new Error("Для удалённого центра мониторинга нужен HTTPS.");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("Укажите адрес без логина, пароля и параметров.");
  }
  return url.origin + url.pathname.replace(/\/$/, "");
}

function isLoopback(url) {
  return ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
}

function preferredHub(saved, current) {
  if (!["http:", "https:"].includes(current.protocol)) return saved || "";
  if (!saved) return current.origin;
  try {
    if (isLoopback(current) && isLoopback(new URL(saved))) return current.origin;
  } catch { return current.origin; }
  return saved;
}

async function request(path, options = {}) {
  const base = state.base, token = state.token;
  const { timeoutMs = 12000, signal: externalSignal, ...fetchOptions } = options;
  const headers = { Accept: "application/json", ...options.headers };
  if (options.body) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  const controller = new AbortController();
  const abort = () => controller.abort();
  if (externalSignal?.aborted) controller.abort();
  else externalSignal?.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${base}${path}`, { ...fetchOptions, headers, signal: controller.signal, cache: "no-store" });
    let payload = {};
    const raw = await response.text();
    if (raw) {
      try { payload = JSON.parse(raw); } catch { throw new Error("Центр мониторинга вернул неверный ответ."); }
    }
    if (!response.ok) {
      // A refresh can see the old session revoked while the password-change
      // response is still in flight. Let that response show the re-login note.
      if (response.status === 401 && token && state.token === token && state.base === base &&
          (!state.passwordChanging || ["/api/v1/admin/password", "/api/v1/session/password"].includes(path))) logout(false);
      const failure = new Error(payload.error || payload.message || `Ошибка HTTP ${response.status}`);
      failure.status = response.status;
      throw failure;
    }
    return payload;
  } catch (error) {
    if (error.name === "AbortError") throw new Error("Центр мониторинга не ответил вовремя.");
    throw error;
  } finally { clearTimeout(timer); externalSignal?.removeEventListener("abort", abort); }
}

function showError(element, message) { element.textContent = message; element.hidden = false; }
function clearError(element) { element.textContent = ""; element.hidden = true; }

async function enterSession(payload, fallbackUsername) {
  if (typeof payload.token !== "string" || !payload.token) throw new Error("Центр мониторинга не выдал сеанс.");
  state.user = hubSessionUser(payload, fallbackUsername);
  state.token = payload.token;
  state.access = null;
  applyHubPermissions();
  $("password").value = "";
  $("loginNotice").hidden = true;
  if (isLoopback(new URL(state.base)) && new URL(state.base).origin === location.origin) {
    localStorage.removeItem("sovagrid.hub");
  } else {
    localStorage.setItem("sovagrid.hub", state.base);
  }
  $("loginView").hidden = true;
  $("appView").hidden = false;
  await refresh();
  state.timer = setInterval(() => { if (!document.hidden) refresh(); }, 15000);
}

let sshBootstrapActive = false;
async function login(event) {
  event.preventDefault();
  if (sshBootstrapActive) return;
  clearError($("loginError"));
  $("loginButton").disabled = true;
  try {
    state.base = apiBase($("hubUrl").value.trim());
    const payload = await request("/api/v1/session", { method: "POST", body: JSON.stringify({ username: $("username").value.trim(), password: $("password").value }) });
    await enterSession(payload, $("username").value.trim());
  } catch (error) {
    showError($("loginError"), error.message || "Не удалось войти.");
  } finally { $("loginButton").disabled = false; }
}

async function trySSHBootstrap(port) {
  if (port === null) return;
  sshBootstrapActive = true;
  $("hubUrl").value = location.origin;
  const button = $("loginButton");
  button.disabled = true;
  $("loginNotice").textContent = "Входим через SSH…";
  $("loginNotice").hidden = false;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(`http://127.0.0.1:${port}/grant`, {
      method: "GET", mode: "cors", credentials: "omit", cache: "no-store",
      redirect: "error", referrerPolicy: "no-referrer", signal: controller.signal,
    });
    if (!response.ok) throw new Error("local broker refused the handoff");
    const handoff = await response.json();
    if (!handoff || Object.keys(handoff).length !== 1 ||
        typeof handoff.grant !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(handoff.grant)) {
      throw new Error("invalid local handoff");
    }
    await redeemSSHGrant(handoff.grant);
  } catch {
    // The grant may have expired, the broker may be gone, or an older Hub may
    // lack this endpoint. A local password login remains available.
    $("loginNotice").textContent = "Вход через SSH не завершился. Войдите в этот сервер по локальному паролю панели.";
    $("loginNotice").hidden = false;
  } finally {
    clearTimeout(timer);
    sshBootstrapActive = false;
    button.disabled = false;
  }
}

async function redeemSSHGrant(grant) {
  if (location.protocol !== "http:" || location.hostname !== "127.0.0.1" ||
      typeof grant !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(grant)) {
    throw new Error("Invalid SSH grant or panel origin");
  }
  state.base = location.origin;
  const payload = await request("/api/v1/session/ssh-grant", {
    method: "POST", body: JSON.stringify({ grant }), timeoutMs: 12000,
  });
  await enterSession(payload, "admin");
}

// Native WebViews inject the grant directly into the page's JS context after
// their own SSH authentication. It never appears in navigation URLs or storage.
globalThis.sovagridRedeemNativeSSHGrant = async (grant) => {
  if (sshBootstrapActive || state.token || location.protocol !== "http:" ||
      location.hostname !== "127.0.0.1" || typeof grant !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(grant)) return false;
  sshBootstrapActive = true;
  $("hubUrl").value = location.origin;
  $("loginButton").disabled = true;
  $("loginNotice").textContent = "Входим через SSH…";
  $("loginNotice").hidden = false;
  try {
    await redeemSSHGrant(grant);
    return true;
  } catch {
    $("loginNotice").textContent = "Вход через SSH не завершился. Войдите в этот сервер по локальному паролю панели.";
    $("loginNotice").hidden = false;
    return false;
  } finally {
    sshBootstrapActive = false;
    $("loginButton").disabled = false;
  }
};

// The same-origin browser gateway proves SSH access to this Ubuntu host and
// returns the existing one-use Hub grant. Never put it in a URL or storage.
globalThis.sovagridRedeemBrowserSSHGrant = async (grant, landing = null) => {
  const allowedOrigin = location.protocol === "https:" ||
    (location.protocol === "http:" && isLoopback(location));
  if (!allowedOrigin || state.token || typeof grant !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(grant)) {
    throw new Error("SSH-вход доступен только на защищённом адресе этого сервера.");
  }
  if (landing !== null && (typeof landing !== "object" || Array.isArray(landing) ||
      Object.keys(landing).sort().join(",") !== "commands,server" ||
      typeof landing.server !== "string" || [...landing.server].length > 80 ||
      /[\x00-\x1f\x7f]/.test(landing.server) || typeof landing.commands !== "boolean")) {
    throw new Error("Неверный выбранный сервер.");
  }
  state.base = location.origin;
  const payload = await request("/api/v1/session/ssh-grant", {
    method: "POST", body: JSON.stringify({ grant }), timeoutMs: 12000,
  });
  browserSSHLanding = landing && { server: landing.server.trim(), commands: landing.commands };
  try { await enterSession(payload, "admin"); }
  catch (error) { browserSSHLanding = null; throw error; }
};

function resetPasswordSettings() {
  state.passwordChangeSeq++;
  state.passwordChanging = false;
  for (const id of ["currentAdminPassword", "newAdminPassword", "confirmAdminPassword"]) $(id).value = "";
  clearError($("settingsPasswordError"));
  $("changePasswordButton").disabled = false;
}

async function changeAdminPassword(event) {
  event.preventDefault();
  if (state.passwordChanging || !state.token) return;
  clearError($("settingsPasswordError"));
  const current = $("currentAdminPassword").value;
  const next = $("newAdminPassword").value;
  const confirmation = $("confirmAdminPassword").value;
  if (!current || current.length > 1024) {
    showError($("settingsPasswordError"), "Введите текущий пароль."); return;
  }
  if (next.length < 12 || next.length > 1024 || !next.trim()) {
    showError($("settingsPasswordError"), "Новый пароль должен содержать от 12 до 1024 символов."); return;
  }
  if (next === current) {
    showError($("settingsPasswordError"), "Новый пароль должен отличаться от текущего."); return;
  }
  if (next !== confirmation) {
    showError($("settingsPasswordError"), "Новые пароли не совпадают."); return;
  }
  if (globalThis.filesHasUnsavedChanges?.()) {
    showError($("settingsPasswordError"), "Сохраните или отмените правки файла перед сменой пароля."); return;
  }
  const token = state.token, base = state.base, seq = state.passwordChangeSeq;
  const body = JSON.stringify({ current_password: current, new_password: next });
  for (const id of ["currentAdminPassword", "newAdminPassword", "confirmAdminPassword"]) $(id).value = "";
  state.passwordChanging = true;
  $("changePasswordButton").disabled = true;
  try {
    const result = await request(state.user && !state.user.legacy ? "/api/v1/session/password" : "/api/v1/admin/password", { method: "POST", body });
    if (seq !== state.passwordChangeSeq || token !== state.token || base !== state.base) return;
    if (result.changed !== true || result.sessions_revoked !== true) throw new Error("Центр мониторинга вернул неполный ответ.");
    logout(false);
    $("loginNotice").textContent = "Пароль изменён. Войдите с новым паролем.";
    $("loginNotice").hidden = false;
    $("password").focus?.();
  } catch (error) {
    if (seq !== state.passwordChangeSeq || token !== state.token || base !== state.base) return;
    const message = error.status === 403 ? "Текущий пароль неверен." :
      error.status === 429 ? "Слишком много попыток. Повторите через 30 секунд." :
      error.message || "Не удалось сменить пароль.";
    showError($("settingsPasswordError"), message);
  } finally {
    if (seq === state.passwordChangeSeq) {
      state.passwordChanging = false;
      $("changePasswordButton").disabled = false;
    }
  }
}

function logout(revoke = true) {
  const oldToken = state.token;
  const oldBase = state.base;
  serverSetupReset();
  resetAllTerminals(true);
  globalThis.filesReset?.();
  globalThis.amneziaReset?.();
  globalThis.vpnJumpReset?.();
  globalThis.telegramReset?.();
  globalThis.monitoringReset?.();
  globalThis.inodeReset?.();
  globalThis.publicWebReset?.();
  globalThis.localWebReset?.();
  globalThis.journalReset?.();
  globalThis.usersReset?.();
  globalThis.backupsReset?.();
  globalThis.hostBackupsReset?.();
  globalThis.accessReset?.();
  globalThis.processInventoryReset?.();
  globalThis.containerLogsReset?.();
  globalThis.containerActionReset?.();
  globalThis.containerAlertsReset?.();
  globalThis.filesystemAlertsReset?.();
  globalThis.serviceControlReset?.();
  globalThis.checksReset?.();
  resetPasswordSettings();
  if (state.timer) clearInterval(state.timer);
  state.timer = null;
  state.token = "";
  browserSSHLanding = null;
  const sshLandingNotice = $("sshLandingNotice");
  if (sshLandingNotice) { sshLandingNotice.hidden = true; sshLandingNotice.textContent = ""; }
  state.user = null;
  state.access = { mode: "all", revision: 0, unrestricted_admin: true };
  state.refreshSeq++;
  state.servers = [];
  state.incidents = [];
  state.jobs = [];
  state.audit = [];
  state.vpn = null;
  state.vpnInventoryTargetId = null;
  state.selectedId = null;
  globalThis.maintenanceReset?.();
  state.view = "overview";
  state.firstLoad = true;
  state.startTelegram = null;
  state.startTelegramLoading = false;
  state.pendingCommand = "";
  state.pendingServerId = null;
  state.pendingCommandKey = null;
  state.submittingCommandKey = null;
  state.commandSubmitting = false;
  state.vpnTargetId = null;
  state.vpnPending = null;
  state.vpnSubmittingKey = null;
  state.vpnActionJobId = null;
  state.vpnActionJob = null;
  sealedPrepareSeq++;
  pendingSealedExport = null;
  activeSealedExport = null;
  for (const url of sealedDownloadUrls) URL.revokeObjectURL(url);
  sealedDownloadUrls.clear();
  state.history = [];
  $("commandInput").value = "";
  $("confirmCommandText").textContent = "";
  $("agentToken").textContent = "";
  $("serverId").textContent = "";
  $("newServerName").value = "";
  $("copyTokenButton").textContent = "Копировать токен";
  $("jobsList").replaceChildren();
  $("auditList").replaceChildren();
  if ($("confirmCommandDialog").open) $("confirmCommandDialog").close();
  if ($("tokenDialog").open) $("tokenDialog").close();
  if ($("addServerDialog").open) $("addServerDialog").close();
  if ($("vpnActionDialog").open) $("vpnActionDialog").close();
  $("vpnActionJobPanel").hidden = true;
  $("vpnActionJobOutput").textContent = "";
  $("vpnProfileDownload").hidden = true;
  $("vpnProfileShare").hidden = true;
  $("vpnProfileStatus").textContent = "";
  $("vpnExportInstance").value = "";
  $("vpnExportClient").value = "";
  $("vpnExportRoute").value = "split";
  $("vpnExportButton").disabled = false;
  $("vpnRemoveName").value = "";
  $("runCommandButton").disabled = false;
  $("cancelCommandButton").disabled = false;
  $("refreshButton").disabled = false;
  $("appView").hidden = true;
  $("loginView").hidden = false;
  if (revoke && oldToken) {
    fetch(`${oldBase}/api/v1/session`, { method: "DELETE", headers: { Authorization: `Bearer ${oldToken}` }, cache: "no-store", keepalive: true }).catch(() => {});
  }
}

async function refresh() {
  if (!state.token || globalThis.publicWebApplying?.() || globalThis.localWebApplying?.()) return;
  const seq = ++state.refreshSeq, token = state.token, base = state.base;
  const current = () => seq === state.refreshSeq && token === state.token && base === state.base;
  $("refreshButton").disabled = true;
  try {
    if (state.user && !state.user.legacy) {
      const [session, access] = await Promise.all([
        request("/api/v1/session"), hubLoadSessionAccess(state.user),
      ]);
      const identity = hubSessionUser(session);
      if (!current()) return;
      if (identity.legacy || identity.id !== state.user.id) throw new Error("Не удалось подтвердить владельца сеанса.");
      state.user = identity;
      state.access = access;
    } else if (state.user?.legacy) {
      state.access = { mode: "all", revision: 0, unrestricted_admin: true };
    }
    applyHubPermissions();
    const [serversPayload, incidentsPayload] = await Promise.all([request("/api/v1/servers"), request("/api/v1/incidents")]);
    if (!current()) return;
    state.servers = Array.isArray(serversPayload.servers) ? serversPayload.servers : [];
    state.incidents = Array.isArray(incidentsPayload.incidents) ? incidentsPayload.incidents : [];
    if (state.firstLoad) {
      if (!state.servers.length && state.view === "overview" && hubCanGlobalAdmin()) state.view = "start";
      state.firstLoad = false;
    }
    if (!state.servers.some((server) => String(server.id) === String(state.selectedId))) {
      state.selectedId = state.servers[0]?.id ?? null;
    }
    if (browserSSHLanding) {
      const landing = browserSSHLanding;
      browserSSHLanding = null;
      const wanted = landing.server.toLowerCase();
      const idMatches = state.servers.filter((server) => String(server.id).toLowerCase() === wanted);
      const nameMatches = idMatches.length ? [] : state.servers.filter((server) =>
        String(server.name || "").trim().toLowerCase() === wanted);
      const matches = idMatches.length ? idMatches : nameMatches;
      const selected = wanted && matches.length === 1 ? matches[0] : null;
      if (selected) state.selectedId = selected.id;
      if (landing.commands && (!wanted || selected)) state.view = "commands";
      const notice = $("sshLandingNotice");
      if (wanted && !selected && notice) {
        notice.textContent = "Выбранный сервер не найден среди доступных вам серверов. Открыт сервер по умолчанию; выберите нужный в списке.";
        notice.hidden = false;
      }
    }
    globalThis.processInventorySelectedServer?.(state.selectedId);
    globalThis.containerLogsSelectedServer?.(state.selectedId);
    globalThis.containerActionSelectedServer?.(state.selectedId);
    globalThis.containerAlertsSelectedServer?.(state.selectedId);
    globalThis.filesystemAlertsSelectedServer?.(state.selectedId);
    globalThis.serviceControlSelectedServer?.(state.selectedId);
    applyHubPermissions();
    globalThis.maintenanceSelectedServer?.(state.selectedId);
    globalThis.checksSelectedServer?.(state.selectedId);
    renderSidebar();
    renderWorkspace();
    const details = [];
    if (state.selectedId !== null) {
      const server = state.servers.find((item) => String(item.id) === String(state.selectedId));
      renderServer(server);
    }
    if (state.selectedId !== null && state.view === "overview") {
      details.push(request(`/api/v1/servers/${encodeURIComponent(state.selectedId)}/metrics?limit=60`).then((history) => {
        if (current()) renderHistory(Array.isArray(history.metrics) ? history.metrics : []);
      }));
      if (globalThis.maintenanceRefresh) details.push(globalThis.maintenanceRefresh());
      if (globalThis.checksRefresh) details.push(globalThis.checksRefresh());
      if (globalThis.containerAlertsRefresh) details.push(globalThis.containerAlertsRefresh());
      if (globalThis.filesystemAlertsRefresh) details.push(globalThis.filesystemAlertsRefresh());
    }
    if (state.view === "commands") {
      details.push(request("/api/v1/jobs").then((jobs) => {
        if (!current()) return;
        state.jobs = Array.isArray(jobs.jobs)
          ? jobs.jobs.map(sanitizeJobForHistory).filter(Boolean) : [];
        renderJobs();
      }));
    }
    if (state.view === "journal" && globalThis.journalRefresh) {
      details.push(globalThis.journalRefresh());
    }
    if (state.view === "audit") {
      details.push(request("/api/v1/audit").then((audit) => {
        if (!current()) return;
        state.audit = Array.isArray(audit.events) ? audit.events : [];
        renderAudit();
      }));
    }
    if (state.view === "telegram" && globalThis.telegramRefresh) {
      details.push(globalThis.telegramRefresh());
    }
    if (state.view === "start") {
      state.startTelegramLoading = true;
      renderStart();
      details.push(request("/api/v1/telegram").then((payload) => {
        if (!current()) return;
        const telegram = payload.telegram;
        state.startTelegram = telegram && typeof telegram.configured === "boolean" &&
          typeof telegram.connected === "boolean" && typeof telegram.polling === "boolean"
          ? { configured: telegram.configured, connected: telegram.connected, polling: telegram.polling }
          : null;
      }).catch(() => { if (current()) state.startTelegram = null; }).finally(() => {
        if (current()) { state.startTelegramLoading = false; renderStart(); }
      }));
    }
    if (state.view === "settings" && globalThis.monitoringRefresh) {
      details.push(globalThis.monitoringRefresh());
    }
    if (state.view === "settings" && globalThis.inodeRefresh) {
      details.push(globalThis.inodeRefresh());
    }
    if (state.view === "settings" && hubCanGlobalAdmin() && globalThis.publicWebRefresh) {
      details.push(globalThis.publicWebRefresh());
    }
    if (state.view === "settings" && hubCanGlobalAdmin() && globalThis.localWebRefresh) {
      details.push(globalThis.localWebRefresh());
    }
    if (state.view === "settings" && hubCanGlobalAdmin() && globalThis.usersRefresh) {
      details.push(globalThis.usersRefresh());
    }
    if (state.view === "settings" && hubCanGlobalAdmin() && globalThis.backupsRefresh) {
      details.push(globalThis.backupsRefresh());
    }
    if (state.view === "settings" && hubCanGlobalAdmin() && globalThis.hostBackupsRefresh) {
      details.push(globalThis.hostBackupsRefresh());
    }
    if (state.view === "vpn") {
      renderVpnControls();
      details.push(refreshVpnInventory(current));
      if (state.vpnActionJobId) {
        details.push(request(`/api/v1/jobs/${encodeURIComponent(state.vpnActionJobId)}`).then((payload) => {
          if (!current()) return;
          state.vpnActionJob = payload.job || null;
          renderVpnActionJob();
        }));
      }
    }
    const results = await Promise.allSettled(details);
    if (!current()) return;
    const failure = results.find((result) => result.status === "rejected");
    if (failure) throw failure.reason;
    $("refreshTime").textContent = `Обновлено ${new Intl.DateTimeFormat("ru", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date())}`;
    clearError($("globalError"));
  } catch (error) {
    if (current()) {
      showError($("globalError"), error.message || "Не удалось обновить данные.");
      if (state.view === "overview") $("topProcessesStatus").textContent = "Не удалось обновить список процессов. Показаны последние полученные данные.";
    }
  } finally { if (current()) $("refreshButton").disabled = false; }
}

function renderSidebar() {
  const list = $("serverList");
  list.replaceChildren();
  $("serverCount").textContent = String(state.servers.length);
  for (const server of state.servers) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `server-item ${server.online ? "online" : server.last_seen ? "offline" : ""} ${String(server.id) === String(state.selectedId) ? "active" : ""}`;
    button.setAttribute("aria-current", String(server.id) === String(state.selectedId) ? "page" : "false");
    const dot = document.createElement("span"); dot.className = "server-dot"; dot.setAttribute("aria-hidden", "true");
    const name = document.createElement("span"); name.textContent = String(server.name || `Сервер ${server.id}`);
    button.append(dot, name);
    button.addEventListener("click", () => {
      const notice = $("sshLandingNotice");
      if (notice) { notice.hidden = true; notice.textContent = ""; }
      if (String(state.selectedId) !== String(server.id)) {
        if (globalThis.filesHasUnsavedChanges?.()) {
          setView("files");
          globalThis.filesWarnUnsavedChanges?.();
          return;
        }
        globalThis.filesReset?.();
        globalThis.journalReset?.();
        globalThis.containerLogsReset?.();
        globalThis.containerActionReset?.();
        globalThis.containerAlertsReset?.();
        globalThis.filesystemAlertsReset?.();
      }
      state.selectedId = server.id;
      if (state.view === "vpn") state.vpnTargetId = server.id;
      globalThis.processInventorySelectedServer?.(state.selectedId);
      globalThis.containerLogsSelectedServer?.(state.selectedId);
      globalThis.containerActionSelectedServer?.(state.selectedId);
      globalThis.containerAlertsSelectedServer?.(state.selectedId);
      globalThis.filesystemAlertsSelectedServer?.(state.selectedId);
      globalThis.serviceControlSelectedServer?.(state.selectedId);
      globalThis.maintenanceSelectedServer?.(state.selectedId);
      globalThis.checksSelectedServer?.(state.selectedId);
      renderSidebar(); renderServer(server); renderHistory([]); renderJobs(); renderEvents(); refresh();
    });
    list.append(button);
  }
}

const viewLabels = {
  start: ["Настройка системы", "Начало работы"],
  overview: ["Обзор инфраструктуры", "Панель управления"],
  commands: ["Операции с сервером", "Команды"],
  journal: ["Диагностика служб", "Журналы systemd"],
  files: ["Файлы сервера", "Файлы"],
  incidents: ["Контроль состояния", "События"],
  audit: ["Безопасность", "Журнал действий"],
  vpn: ["Сетевые сервисы", "VPN и Amnezia"],
  telegram: ["Уведомления и роли", "Telegram-бот"],
  settings: ["Учётная запись", "Настройки"],
};

function renderWorkspace() {
  applyHubPermissions();
  const hasServer = state.servers.length > 0;
  const globalView = ["start", "audit", "vpn", "telegram", "settings"].includes(state.view);
  const [eyebrow, title] = viewLabels[state.view] || viewLabels.overview;
  $("viewEyebrow").textContent = eyebrow;
  $("viewTitle").textContent = title;
  $("emptyState").hidden = hasServer || globalView;
  document.querySelectorAll("[data-view-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.viewPanel !== state.view || (!hasServer && !globalView);
  });
  document.querySelectorAll("[data-view]").forEach((button) => {
    const active = button.dataset.view === state.view;
    button.classList.toggle("active", active);
    button.setAttribute("aria-current", active ? "page" : "false");
  });
  if (state.view === "commands" && terminalClient.term) setTimeout(fitTerminal, 0);
  if (state.view === "files") globalThis.filesViewActivated?.();
  if (state.view === "journal") globalThis.journalRender?.();
  if (state.view === "start") renderStart();
}

function startBadge(id, label, ready = false) {
  const badge = $(id);
  badge.textContent = label;
  badge.className = `status-badge${ready ? "" : " waiting"}`;
}

function renderStart() {
  const servers = state.servers;
  const online = servers.filter((server) => server.online).length;
  const reported = servers.some((server) => server.last_seen);
  const commandAccess = servers.some((server) => server.online && server.remote_commands_enabled);
  const telegram = state.startTelegram;
  const telegramReady = Boolean(telegram?.connected);
  startBadge("startServersBadge", !servers.length ? "Нет серверов" : online ? `${online} на связи` : reported ? "Нет связи" : "Ожидают Agent", online > 0);
  $("startServersText").textContent = !servers.length
    ? "Создайте запись Ubuntu-сервера, установите Agent и дождитесь первого отчёта."
    : `В списке: ${servers.length}. ${online ? `Сейчас на связи: ${online}.` : reported ? "Сейчас все не на связи." : "Agent ещё не прислал данные."}`;
  const serverAction = $("startServersAction");
  serverAction.dataset.startAction = servers.length ? "overview" : "add";
  serverAction.textContent = servers.length ? "Открыть обзор" : "Добавить сервер";
  startBadge("startMonitoringBadge", online ? "Метрики идут" : reported ? "Нет связи" : "Ожидает Agent", online > 0);
  $("startMonitoringText").textContent = online
    ? "Сервер передаёт состояние в Hub. Проверьте пороги CPU, памяти, диска и времени без связи."
    : "Метрики и тревоги появятся после первого отчёта Agent. Пороги можно менять в настройках.";
  startBadge("startCommandsBadge", commandAccess ? "Разрешено в Hub" : servers.length ? "Выключено в Hub" : "Нужен сервер", commandAccess);
  $("startCommandsText").textContent = commandAccess
    ? "Hub разрешает команды. Agent должен разрешать их локально; для интерактивного терминала нужно отдельное разрешение."
    : "Для команд включите доступ в Hub и на Agent. Интерактивный терминал разрешается отдельно.";
  startBadge("startFilesBadge", servers.length ? "Проверьте Agent" : "Нужен сервер");
  startBadge("startVpnBadge", "Опционально");
  startBadge("startTelegramBadge", state.startTelegramLoading ? "Проверяем" : !telegram ? "Нет данных" :
    !telegram.configured ? "Не настроен" : telegramReady ? "На связи" : telegram.polling ? "Подключается" : "Нет связи", telegramReady);
  $("startTelegramText").textContent = !telegram
    ? "Откройте раздел Telegram, чтобы проверить бота и роли пользователей."
    : !telegram.configured ? "Вставьте токен BotFather прямо в панели. Затем одобрите запросы и назначьте роли."
    : telegramReady ? "Бот подключён. Запросы доступа и роли пользователей управляются в панели."
      : "Токен сохранён, но бот ещё не на связи. Откройте раздел для проверки состояния.";
  const nextButton = $("startPrimaryButton");
  if (!servers.length) {
    $("startNextHeading").textContent = "Подключите первый сервер";
    $("startNextText").textContent = "Создайте запись Ubuntu-сервера и установите Agent на эту машину.";
    nextButton.dataset.startAction = "add";
    nextButton.textContent = "Добавить сервер";
  } else if (!online) {
    $("startNextHeading").textContent = "Дождитесь связи с Agent";
    $("startNextText").textContent = "Проверьте выбранный сервер: после первого отчёта появятся метрики и состояние.";
    nextButton.dataset.startAction = "overview";
    nextButton.textContent = "Открыть сервер";
  } else if (telegram && !telegram.configured) {
    $("startNextHeading").textContent = "Настройте уведомления";
    $("startNextText").textContent = "Добавьте токен BotFather через форму в панели и назначьте роли пользователям.";
    nextButton.dataset.startAction = "telegram";
    nextButton.textContent = "Открыть Telegram";
  } else {
    $("startNextHeading").textContent = "Проверьте правила оповещений";
    $("startNextText").textContent = "Настройте пороги и время без связи для подключённых серверов.";
    nextButton.dataset.startAction = "settings";
    nextButton.textContent = "Открыть настройки";
  }
}

function setView(view) {
  if (!viewLabels[view] || state.view === view ||
      (!hubCanAdmin() && SERVER_ADMIN_VIEWS.has(view)) ||
      (!hubCanGlobalAdmin() && GLOBAL_ADMIN_VIEWS.has(view)) ||
      (!hubCanAudit() && ADMIN_AUDIT_VIEWS.has(view))) return;
  if (state.view === "commands") $("terminalInput").value = "";
  if (state.view === "journal") globalThis.journalReset?.();
  if (state.view === "vpn") globalThis.vpnJumpReset?.();
  if (state.view === "overview") {
    globalThis.containerLogsReset?.();
    globalThis.containerActionReset?.();
    globalThis.containerAlertsReset?.();
    globalThis.filesystemAlertsReset?.();
  }
  state.view = view;
  renderWorkspace();
  if (view === "vpn") {
    renderVpnControls();
    renderVpn({ source_status: "loading" }, vpnInventoryContext(state.vpnTargetId));
  }
  if (state.token) refresh();
}

function percent(value) { const n = number(value); return n === null ? "—" : `${Math.round(clamp(n))}%`; }
function bytes(value) {
  const n = number(value);
  if (n === null || n < 0) return "—";
  const units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let scale = 0, amount = n;
  while (amount >= 1024 && scale < units.length - 1) { amount /= 1024; scale++; }
  return `${amount < 10 && scale > 0 ? amount.toFixed(1) : Math.round(amount)} ${units[scale]}`;
}
function duration(seconds) {
  const n = number(seconds);
  if (n === null || n < 0) return "—";
  const days = Math.floor(n / 86400), hours = Math.floor((n % 86400) / 3600), minutes = Math.floor((n % 3600) / 60);
  return days ? `${days} д ${hours} ч` : hours ? `${hours} ч ${minutes} мин` : `${minutes} мин`;
}
function timestamp(value) {
  if (value === null || value === undefined || value === "") return "—";
  const numeric = number(value);
  const date = numeric !== null ? new Date(numeric * 1000) : new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : new Intl.DateTimeFormat("ru", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }).format(date);
}
function setMeter(name, value) {
  const bar = $(`${name}Bar`);
  const n = number(value);
  bar.style.width = n === null ? "0%" : `${clamp(n)}%`;
  bar.className = n >= 90 ? "danger" : n >= 75 ? "warn" : "";
  $(`${name}Value`).textContent = percent(value);
}

function renderServer(server) {
  if (!server) return;
  $("serverName").textContent = String(server.name || `Сервер ${server.id}`);
  const status = $("serverStatus");
  status.textContent = server.online ? "Работает" : server.last_seen ? "Нет связи" : "Ожидание агента";
  status.className = `status-badge ${server.online ? "" : server.last_seen ? "offline" : "waiting"}`;
  $("lastSeen").textContent = server.last_seen ? `Последний сигнал: ${timestamp(server.last_seen)}` : "Агент ещё не прислал данные";
  $("serverIdDetail").textContent = String(server.id ?? "—");
  const latest = server.latest || {};
  setMeter("cpu", latest.cpu_percent);
  setMeter("memory", latest.memory_percent);
  setMeter("disk", number(latest.disk_total_bytes) === 0 ? null : latest.disk_percent);
  $("uptimeValue").textContent = duration(latest.uptime_seconds);
  $("uptimeBar").style.width = latest.uptime_seconds ? "100%" : "0%";
  $("memoryDetail").textContent = latest.memory_total_bytes ? `Всего ${bytes(latest.memory_total_bytes)}` : "Использование RAM";
  $("diskDetail").textContent = number(latest.disk_total_bytes) === 0 ? "Метрика корневого раздела недоступна" : latest.disk_total_bytes ? `Всего ${bytes(latest.disk_total_bytes)}` : "Заполненность корневого раздела";
  $("loadValue").textContent = number(latest.load1) === null ? "—" : Number(latest.load1).toFixed(2);
  $("networkRx").textContent = bytes(latest.network_rx_bytes);
  $("networkTx").textContent = bytes(latest.network_tx_bytes);
  $("sampleTime").textContent = timestamp(latest.collected_at);
  renderAdvanced(latest.details || {}, Boolean(server.online));
  renderClock(latest.details?.clock, Boolean(server.online));
  renderTopProcesses(latest.details?.top_processes, server);
  renderContainers(latest.details?.containers, server);
  globalThis.containerLogsRender?.(latest.details?.containers, server);
  globalThis.containerActionRenderInventory?.(latest.details?.containers, server);
  globalThis.containerAlertsRenderInventory?.();
  globalThis.filesystemAlertsRenderInventory?.();
  renderIncidents(server.id);
  globalThis.maintenanceRender?.(server);
  renderCommandServer(server);
  renderTerminalControls();
  renderEvents();
}

function renderClock(clock, online) {
  const data = clock && typeof clock === "object" && !Array.isArray(clock) ? clock : {};
  const epoch = data.system_utc_epoch;
  const validEpoch = Number.isSafeInteger(epoch) && epoch >= 1 && epoch <= 253402300799;
  $("clockUtcValue").textContent = validEpoch
    ? `${new Date(epoch * 1000).toISOString().slice(0, 19).replace("T", " ")} UTC` : "—";
  $("clockSyncValue").textContent = data.ntp_synchronized === true ? "Синхронизировано"
    : data.ntp_synchronized === false ? "Нет синхронизации" : "Неизвестно";
  $("clockZoneValue").textContent = typeof data.timezone === "string" &&
    /^[A-Za-z0-9_.+-]+(?:\/[A-Za-z0-9_.+-]+){0,4}$/.test(data.timezone) ? data.timezone : "—";
  const offset = Number.isSafeInteger(data.rtc_offset_seconds) &&
    Math.abs(data.rtc_offset_seconds) <= 2**31 - 1 ? data.rtc_offset_seconds : null;
  $("clockRtcOffsetValue").textContent = offset === null ? "Недоступно" :
    offset === 0 ? "Совпадает" :
      `${offset > 0 ? "+" : "−"}${Math.abs(offset)} с · RTC ${offset > 0 ? "впереди" : "позади"}`;
  const unsynchronized = data.ntp_synchronized === false;
  const rtcDrift = offset !== null && Math.abs(offset) >= 30;
  const warning = $("clockWarning");
  warning.hidden = !unsynchronized && !rtcDrift;
  warning.textContent = warning.hidden ? "" :
    `${online ? "Проверьте часы сервера" : "По последнему отчёту часы сервера требовали проверки"}: ` +
    [unsynchronized ? "NTP не подтверждает синхронизацию" : null,
      rtcDrift ? `RTC расходится с системным временем на ${Math.abs(offset)} с` : null]
      .filter(Boolean).join("; ") + ".";
}

function renderTopProcesses(items, server) {
  const rows = $("topProcessesRows"), table = $("topProcessesTable"), status = $("topProcessesStatus");
  rows.replaceChildren();
  table.hidden = true;
  if (!server.online) {
    status.textContent = server.last_seen ? "Сервер не отвечает. Актуальный список процессов недоступен." : "Список появится после первого отчёта агента.";
    return;
  }
  if (!Array.isArray(items)) {
    status.textContent = "Агент пока не передал список процессов.";
    return;
  }
  if (!items.length) {
    status.textContent = "Нет процессов с доступными данными RSS.";
    return;
  }
  if (items.length > 10 || items.some((item) => !Number.isInteger(item?.pid) || item.pid < 1 ||
      typeof item.name !== "string" || !/^[A-Za-z0-9_.:+@-]{1,16}$/.test(item.name) ||
      number(item.rss_bytes) === null || number(item.rss_bytes) <= 0)) {
    status.textContent = "Не удалось отобразить список процессов: некорректные данные.";
    return;
  }
  for (const item of items) {
    const row = document.createElement("tr");
    const pid = document.createElement("td"), name = document.createElement("td"), rss = document.createElement("td");
    pid.textContent = String(item.pid);
    name.textContent = item.name;
    rss.textContent = bytes(item.rss_bytes);
    row.append(pid, name, rss); rows.append(row);
  }
  table.hidden = false;
  status.textContent = `${items.length} ${items.length === 1 ? "процесс" : items.length < 5 ? "процесса" : "процессов"} · снимок из последнего отчёта`;
}

function renderContainers(snapshot, server) {
  const list = $("containersList"), freshness = $("containersFreshness"), count = $("containersCount");
  list.replaceChildren();
  count.textContent = "—";
  if (!snapshot || snapshot.version !== 1 || !Array.isArray(snapshot.engines) || snapshot.engines.length !== 2 ||
      !Number.isSafeInteger(snapshot.collected_at) || snapshot.collected_at < 1 || snapshot.collected_at > 253402300799) {
    freshness.className = "container-freshness";
    freshness.textContent = "Мониторинг контейнеров пока не включён или Agent ещё не передал снимок.";
    return;
  }
  const age = Math.max(0, Math.floor(Date.now() / 1000 - snapshot.collected_at));
  const stale = !server.online || age > 90;
  const ageText = age < 60 ? `${age} с` : age < 3600 ? `${Math.floor(age / 60)} мин` :
    age < 86400 ? `${Math.floor(age / 3600)} ч` : `${Math.floor(age / 86400)} д`;
  freshness.textContent = `${stale ? "Устаревший снимок" : "Актуальный снимок"} · ${ageText} назад · ` +
    `${new Date(snapshot.collected_at * 1000).toISOString().slice(0, 19).replace("T", " ")} UTC`;
  freshness.className = `container-freshness${stale ? " stale" : ""}`;
  const reasonLabels = { no_socket: "Локальный сокет недоступен", no_access: "Нет прав на локальный сокет", error: "Ошибка чтения источника" };
  const stateLabels = { created: "Создан", running: "Работает", paused: "Приостановлен", restarting: "Перезапускается",
    removing: "Удаляется", exited: "Остановлен", dead: "Ошибка", unknown: "Неизвестно" };
  const healthLabels = { starting: "Проверка запускается", healthy: "Здоров", unhealthy: "Проверка не пройдена" };
  let total = 0;
  for (const [position, expected] of ["docker", "podman"].entries()) {
    const engine = snapshot.engines[position];
    if (!engine || engine.engine !== expected || !["ok", "unavailable"].includes(engine.source_status) ||
        !Array.isArray(engine.containers) || engine.containers.length > 12) {
      freshness.className = "container-freshness stale";
      freshness.textContent = "Некорректные данные мониторинга контейнеров.";
      list.replaceChildren();
      return;
    }
    const section = document.createElement("section"); section.className = "container-engine";
    const heading = document.createElement("div"); heading.className = "container-engine-heading";
    const title = document.createElement("h3"); title.textContent = expected === "docker" ? "Docker" : "Podman";
    const badge = document.createElement("span"); badge.className = `container-engine-badge${engine.source_status === "ok" ? "" : " unavailable"}`;
    badge.textContent = engine.source_status === "ok" ? `${engine.containers.length}${engine.truncated ? "+" : ""}` : "Недоступен";
    heading.append(title, badge); section.append(heading);
    if (engine.source_status !== "ok") {
      const message = document.createElement("p"); message.className = "container-empty";
      message.textContent = reasonLabels[engine.reason] || "Нет доступа к источнику";
      section.append(message);
    } else if (!engine.containers.length) {
      const message = document.createElement("p"); message.className = "container-empty";
      message.textContent = "Контейнеров нет."; section.append(message);
    } else {
      const grid = document.createElement("div"); grid.className = "container-grid";
      for (const item of engine.containers) {
        if (typeof item?.id !== "string" || !/^[0-9a-f]{64}$/.test(item.id) ||
            typeof item.name !== "string" || typeof item.image !== "string" ||
            !Object.hasOwn(stateLabels, item.state)) continue;
        const card = document.createElement("article"); card.className = "container-card";
        const top = document.createElement("div"); top.className = "container-card-top";
        const name = document.createElement("strong"); name.textContent = item.name;
        const state = document.createElement("span"); state.textContent = stateLabels[item.state];
        state.className = `container-state${item.state === "running" && item.health !== "unhealthy" ? " running" : ""}`;
        top.append(name, state); card.append(top);
        const image = document.createElement("p"); image.className = "container-image"; image.textContent = item.image;
        const metadata = document.createElement("p"); metadata.className = "container-meta";
        metadata.textContent = `${item.id.slice(0, 12)} · ${healthLabels[item.health] || "Проверка здоровья недоступна"} · ` +
          `перезапусков: ${Number.isSafeInteger(item.restarts) && item.restarts >= 0 ? item.restarts : "—"}`;
        const usage = document.createElement("p"); usage.className = "container-usage";
        usage.textContent = `CPU ${number(item.cpu_percent) === null ? "—" : `${Number(item.cpu_percent).toFixed(1)}%`} · RAM ${bytes(item.memory_bytes)}`;
        card.append(image, metadata, usage); grid.append(card); total++;
      }
      section.append(grid);
      if (engine.truncated) {
        const note = document.createElement("p"); note.className = "container-empty";
        note.textContent = "Показаны только первые 12 контейнеров этого источника."; section.append(note);
      }
    }
    list.append(section);
  }
  count.textContent = String(total);
}

function rootInodePercent(details) {
  const root = Array.isArray(details.filesystems) ? details.filesystems.find((item) => item?.mountpoint === "/") : null;
  if (!root || !Number.isSafeInteger(root.inodes_total) || !Number.isSafeInteger(root.inodes_available) ||
      root.inodes_total <= 0 || root.inodes_available < 0 || root.inodes_available > root.inodes_total ||
      typeof root.inodes_used_percent !== "number" || !Number.isFinite(root.inodes_used_percent)) return null;
  const calculated = Math.round(10000 * (1 - root.inodes_available / root.inodes_total)) / 100;
  return Math.abs(calculated - root.inodes_used_percent) <= 0.05 ? calculated : null;
}

function renderAdvanced(details, online = false) {
  const swap = details.swap || {};
  $("swapValue").textContent = number(swap.total_bytes) === 0 ? "Нет" : number(swap.used_percent) === null ? "—" : percent(swap.used_percent);
  $("load5Value").textContent = number(details.load5) === null ? "—" : Number(details.load5).toFixed(2);
  $("load15Value").textContent = number(details.load15) === null ? "—" : Number(details.load15).toFixed(2);
  const running = number(details.processes?.running), blocked = number(details.processes?.blocked);
  $("processValue").textContent = running === null ? "—" : `${running} активных${blocked === null ? "" : ` · ${blocked} ожидают`}`;
  const failedServices = number(details.services?.failed_count);
  $("failedServicesValue").textContent = failedServices === null ? "—" : String(failedServices);

  const filesystems = Array.isArray(details.filesystems) ? details.filesystems : [];
  const inodeUsed = rootInodePercent(details);
  $("rootInodeStatus").textContent = inodeUsed === null
    ? "Состояние inode корня неизвестно: Agent не передал согласованные счётчики."
    : online ? `Последнее подтверждённое измерение: использовано ${percent(inodeUsed)} inode корня.`
      : `Последнее измерение: использовано ${percent(inodeUsed)} inode корня. Текущее состояние неизвестно: Agent не на связи.`;
  renderAdvancedRows("filesystemsList", filesystems.map((item) => ({
    label: String(item.mountpoint || "Раздел"),
    value: percent(item.used_percent),
    note: `${String(item.fstype || "")} · свободно ${bytes(item.available_bytes)}${item.mountpoint === "/" ? ` · inode ${inodeUsed === null ? "неизвестно" : percent(inodeUsed)}` : number(item.inodes_used_percent) === null || Number(item.inodes_total) <= 0 ? "" : ` · inode ${percent(item.inodes_used_percent)}`}`,
  })));
  const interfaces = Array.isArray(details.interfaces) ? details.interfaces : [];
  renderAdvancedRows("interfacesList", interfaces.map((item) => ({
    label: String(item.name || "Интерфейс"),
    value: `↓ ${bytes(item.rx_bytes)} · ↑ ${bytes(item.tx_bytes)}`,
    note: `Ошибки RX/TX: ${number(item.rx_errors) ?? 0}/${number(item.tx_errors) ?? 0}`,
  })));
  const disks = Array.isArray(details.disk_io) ? details.disk_io : [];
  renderAdvancedRows("diskIoList", disks.map((item) => ({
    label: String(item.device || "Диск"),
    value: `↓ ${bytes(item.read_bytes)} · ↑ ${bytes(item.write_bytes)}`,
    note: "Накоплено с запуска системы",
  })));
  const serviceLabels = { active: "Работает", inactive: "Остановлена", failed: "Ошибка", activating: "Запускается", deactivating: "Останавливается" };
  const units = Array.isArray(details.services?.units) ? details.services.units : [];
  renderAdvancedRows("servicesList", units.map((item) => ({
    label: String(item.name || "Служба"),
    value: serviceLabels[item.active] || "Неизвестно",
    note: String(item.sub || "—"),
  })));
}

function renderAdvancedRows(id, rows) {
  const list = $(id); list.replaceChildren();
  if (!rows.length) { const empty = document.createElement("p"); empty.className = "advanced-empty"; empty.textContent = "Данные пока недоступны"; list.append(empty); return; }
  for (const row of rows) {
    const item = document.createElement("div"); item.className = "advanced-row";
    const top = document.createElement("div"); top.className = "advanced-row-top";
    const label = document.createElement("span"); label.textContent = row.label;
    const value = document.createElement("strong"); value.textContent = row.value;
    const note = document.createElement("p"); note.textContent = row.note;
    top.append(label, value); item.append(top, note); list.append(item);
  }
}

function renderHistory(samples) {
  state.history = samples;
  const labels = { cpu_percent: "Нагрузка CPU", memory_percent: "Использование памяти", disk_percent: "Заполненность диска" };
  $("historyHeading").textContent = labels[state.chartField];
  $("cpuChart").setAttribute("aria-label", `График: ${labels[state.chartField].toLowerCase()}`);
  document.querySelectorAll("[data-chart]").forEach((button) => button.setAttribute("aria-pressed", String(button.dataset.chart === state.chartField)));
  const valid = samples.filter((sample) => number(sample[state.chartField]) !== null &&
    (state.chartField !== "disk_percent" || number(sample.disk_total_bytes) !== 0)).sort((a, b) => Number(a.collected_at) - Number(b.collected_at));
  const area = $("chartArea"), line = $("chartLine");
  if (valid.length < 2) { area.setAttribute("d", ""); line.setAttribute("d", ""); $("chartEmpty").hidden = false; $("chartStart").textContent = "—"; $("chartEnd").textContent = "—"; return; }
  const firstTime = Number(valid[0].collected_at), lastTime = Number(valid.at(-1).collected_at);
  const points = valid.map((sample, index) => [
    lastTime > firstTime ? (Number(sample.collected_at) - firstTime) * 600 / (lastTime - firstTime) : index * 600 / (valid.length - 1),
    150 - clamp(sample[state.chartField]) * 1.2,
  ]);
  const path = points.map(([x, y], index) => `${index ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
  line.setAttribute("d", path);
  area.setAttribute("d", `${path} L600 150 L0 150 Z`);
  $("chartEmpty").hidden = true;
  $("chartStart").textContent = timestamp(valid[0].collected_at);
  $("chartEnd").textContent = timestamp(valid.at(-1).collected_at);
}

function incidentTimeline(incident) {
  if (incident.state === "resolved") {
    const ended = Number(incident.resolved_at || incident.updated_at || 0);
    const started = Number(incident.opened_at || incident.updated_at || 0);
    const seconds = Math.max(0, ended - started);
    const duration = seconds < 60 ? `${seconds} сек` :
      seconds < 3600 ? `${Math.floor(seconds / 60)} мин` :
        `${Math.floor(seconds / 3600)} ч ${Math.floor((seconds % 3600) / 60)} мин`;
    const outcome = incident.kind === "high_root_inodes" ||
      typeof incident.kind === "string" && incident.kind.startsWith("container:") ? "Закрыто" : "Восстановлено";
    return `${outcome}: ${timestamp(ended)} · начало: ${timestamp(started)} · длилось ${duration}`;
  }
  return `Тревога с ${timestamp(incident.opened_at || incident.updated_at)} · обновлено: ${timestamp(incident.updated_at || incident.opened_at)}`;
}

function incidentLabel(incident) {
  if (typeof incident.kind === "string" && incident.kind.startsWith("check:")) {
    return typeof incident.subject === "string" && incident.subject ?
      `Недоступность проверки «${incident.subject}»` : "Недоступность проверки";
  }
  if (typeof incident.kind === "string" && incident.kind.startsWith("tls:")) {
    return typeof incident.subject === "string" && incident.subject ?
      `Истекает HTTPS-сертификат проверки «${incident.subject}»` : "Истекает HTTPS-сертификат проверки";
  }
  if (typeof incident.kind === "string" && /^container:[0-9a-f]{64}$/.test(incident.kind)) {
    return typeof incident.subject === "string" && incident.subject ?
      `Проблема с Docker-контейнером «${incident.subject}»` :
      `Проблема с Docker-контейнером #${incident.kind.slice(10, 18)}`;
  }
  if (typeof incident.kind === "string" && /^filesystem:(space|inodes):[0-9a-f]{64}$/.test(incident.kind)) {
    const metric = incident.kind.startsWith("filesystem:space:") ? "места" : "inode";
    return typeof incident.subject === "string" && incident.subject ?
      `Заканчивается ${metric} на «${incident.subject}»` :
      `Заканчивается ${metric} на диске #${incident.kind.slice(-64, -56)}`;
  }
  const labels = { high_cpu: "Высокая нагрузка CPU", high_memory: "Мало свободной памяти", high_disk: "Заканчивается место на диске", high_root_inodes: "Заканчиваются inode корневой системы", failed_services: "Сбой системных служб", offline: "Нет связи с сервером" };
  return labels[incident.kind] || String(incident.kind || "Событие");
}

function incidentTlsDetail(incident) {
  if (incident.state !== "firing" || typeof incident.kind !== "string" || !incident.kind.startsWith("tls:") ||
      typeof incident.current_value !== "number" || !Number.isFinite(incident.current_value)) return "";
  const days = Math.abs(incident.current_value).toFixed(1);
  const remaining = incident.current_value < 0 ? `Сертификат просрочен на ${days} дн.` : `До истечения ${days} дн.`;
  return `${remaining}${typeof incident.threshold === "number" && Number.isFinite(incident.threshold) ? ` · порог ${incident.threshold} дн.` : ""}`;
}

function incidentInodeDetail(incident) {
  if (incident.kind !== "high_root_inodes" || incident.state !== "firing" ||
      typeof incident.current_value !== "number" || !Number.isFinite(incident.current_value)) return "";
  const value = `Последнее подтверждённое измерение: ${incident.current_value.toFixed(1)}% inode занято`;
  return typeof incident.threshold === "number" && Number.isFinite(incident.threshold)
    ? `${value} · порог ${incident.threshold}%` : value;
}

function renderIncidents(serverId) {
  const incidents = state.incidents.filter((item) => String(item.server_id) === String(serverId)).sort((a, b) => Number(b.updated_at || 0) - Number(a.updated_at || 0)).slice(0, 8);
  $("incidentCount").textContent = String(incidents.filter((item) => item.state === "firing").length);
  const list = $("incidentsList"); list.replaceChildren();
  if (!incidents.length) { const empty = document.createElement("p"); empty.className = "no-incidents"; empty.textContent = "Событий пока нет"; list.append(empty); return; }
  for (const incident of incidents) {
    const card = document.createElement("article"); card.className = `incident ${incident.state === "resolved" ? "resolved" : ""} ${incident.kind === "high_root_inodes" && incident.state === "resolved" ? "inode-closed" : ""}`;
    const dot = document.createElement("span"); dot.className = "incident-dot"; dot.setAttribute("aria-hidden", "true");
    const body = document.createElement("div");
    const title = document.createElement("h3"); title.textContent = incidentLabel(incident);
    const detail = document.createElement("p"); detail.textContent = [incidentTimeline(incident), incidentTlsDetail(incident), incidentInodeDetail(incident)].filter(Boolean).join(" · ");
    body.append(title, detail); card.append(dot, body); list.append(card);
  }
}

function selectedServer() {
  return state.servers.find((server) => String(server.id) === String(state.selectedId));
}

function renderCommandServer(server) {
  if (!server) return;
  $("commandServerName").textContent = String(server.name || server.id);
  const status = $("commandServerStatus");
  status.textContent = server.online ? "На связи" : "Нет связи";
  status.className = `status-badge ${server.online ? "" : "offline"}`;
  const enabled = Boolean(server.remote_commands_enabled);
  $("commandPermissionTitle").textContent = enabled ? "Разрешено в Hub" : "Команды отключены в Hub";
  $("commandPermissionDescription").textContent = enabled
    ? "Для выполнения локальный агент также должен иметь allow_remote_commands=true."
    : "Включите команды для этого сервера в Hub и отдельно в локальной конфигурации агента.";
  $("commandPermissionButton").textContent = enabled ? "Отключить в Hub" : "Разрешить в Hub";
  $("prepareCommandButton").disabled = !enabled || !server.online;
}

function jobState(job) {
  const labels = { queued: "В очереди", delivered: "Выполняется", succeeded: "Успешно", failed: "Ошибка", timed_out: "Превышено время", output_limited: "Вывод ограничен", cancelled: "Отменено" };
  return labels[job.state] || String(job.state || "Неизвестно");
}

function base64UrlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(value, expectedLength, maximumLength = expectedLength) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > Math.ceil(maximumLength * 4 / 3) + 2) {
    throw new Error("Неверный формат зашифрованного профиля.");
  }
  let bytes;
  try {
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "="));
    bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch { throw new Error("Неверный формат зашифрованного профиля."); }
  if ((expectedLength !== null && bytes.length !== expectedLength) || bytes.length > maximumLength || base64UrlEncode(bytes) !== value) {
    throw new Error("Неверный формат зашифрованного профиля.");
  }
  return bytes;
}

function isSealedOutput(output) {
  if (typeof output !== "string") return false;
  // The Hub also returns completed jobs in the generic command history. Hide
  // ciphertext there even after a refresh has discarded the browser key.
  return /"(?:ephemeral_public_key|ciphertext)"\s*:/.test(output);
}

function sealedEnvelope(output) {
  if (!isSealedOutput(output) || output.length > 32768) throw new Error("Зашифрованный профиль отсутствует или повреждён.");
  let envelope;
  try { envelope = JSON.parse(output); }
  catch { throw new Error("Зашифрованный профиль повреждён."); }
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope) || envelope.version !== 1 ||
      Object.keys(envelope).sort().join(",") !== "ciphertext,ephemeral_public_key,nonce,salt,version") {
    throw new Error("Неподдерживаемый формат зашифрованного профиля.");
  }
  const publicKey = base64UrlDecode(envelope.ephemeral_public_key, 65);
  if (publicKey[0] !== 4) throw new Error("Неверный ключ зашифрованного профиля.");
  return {
    publicKey, salt: base64UrlDecode(envelope.salt, 16),
    nonce: base64UrlDecode(envelope.nonce, 12),
    ciphertext: base64UrlDecode(envelope.ciphertext, null, 16384),
  };
}

async function decryptSealedProfile(privateKey, output, name, client) {
  const envelope = sealedEnvelope(output);
  if (envelope.ciphertext.length < 17) throw new Error("Зашифрованный профиль пуст.");
  const ephemeralKey = await crypto.subtle.importKey("raw", envelope.publicKey, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const sharedSecret = await crypto.subtle.deriveBits({ name: "ECDH", public: ephemeralKey }, privateKey, 256);
  const material = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: envelope.salt, info: new TextEncoder().encode(SEALED_PROFILE_INFO) },
    material, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const aad = new TextEncoder().encode(`SovaGrid profile\0${name}\0${client}`);
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: envelope.nonce, additionalData: aad, tagLength: 128 }, aesKey, envelope.ciphertext);
  } catch { throw new Error("Профиль не удалось расшифровать. Запросите его заново."); }
  const bytes = new Uint8Array(plaintext);
  if (!bytes.length || bytes.length > 16384) throw new Error("Получен неверный VPN-профиль.");
  return bytes;
}

function sealedSessionCurrent(exportRequest) {
  return activeSealedExport === exportRequest && state.token === exportRequest.token &&
    state.base === exportRequest.base && String(state.vpnActionJobId) === String(exportRequest.jobId) &&
    String(state.vpnActionJob?.server_id ?? exportRequest.serverId) === String(exportRequest.serverId);
}

async function prepareSealedDownload(exportRequest, job) {
  exportRequest.status = "decrypting";
  renderVpnActionJob();
  let bytes;
  try {
    bytes = await decryptSealedProfile(exportRequest.privateKey, job.output, exportRequest.name, exportRequest.client);
    if (!sealedSessionCurrent(exportRequest)) return;
    exportRequest.file = new File([bytes], `${exportRequest.name}-${exportRequest.client}.conf`, { type: "text/plain" });
    exportRequest.privateKey = null;
    exportRequest.status = "ready";
  } catch {
    if (!sealedSessionCurrent(exportRequest)) return;
    exportRequest.privateKey = null;
    exportRequest.status = "failed";
  } finally {
    if (bytes) bytes.fill(0);
    if (sealedSessionCurrent(exportRequest)) renderVpnActionJob();
  }
}

function privateAwgSettingsHistory(job) {
  const marker = /confirmation_id|settings[_-](?:intent|apply)/i;
  if ([job.action, job.command].some((value) =>
    typeof value === "string" && marker.test(value))) return true;
  const output = job.output;
  if (typeof output === "string") {
    if (marker.test(output)) return true;
    // Recognize valid JSON even if a field name was escaped in transport.
    if (output.length <= 4096 && output.trimStart().startsWith("{")) {
      try {
        const value = JSON.parse(output);
        if (value && typeof value === "object" &&
            (value.action === "settings_intent" || Object.hasOwn(value, "confirmation_id"))) return true;
      } catch { /* A malformed output with an action marker is handled above. */ }
    }
  } else if (output && typeof output === "object" &&
             (output.action === "settings_intent" || Object.hasOwn(output, "confirmation_id"))) return true;
  return Object.hasOwn(job, "confirmation_id");
}

function sanitizeJobForHistory(job) {
  if (!job || typeof job !== "object" || Array.isArray(job)) return null;
  if (!privateAwgSettingsHistory(job)) return job;
  // Only public status fields survive. A future Hub may add command fields;
  // neither the raw output nor a confirmation handle may enter page state.
  return { id: job.id, server_id: job.server_id, state: job.state,
    created_at: job.created_at, exit_code: job.exit_code,
    output: null, awg_settings_redacted: true };
}

function renderJobs() {
  const list = $("jobsList"); list.replaceChildren();
  const jobs = state.jobs.map(sanitizeJobForHistory).filter((job) =>
    job && String(job.server_id) === String(state.selectedId))
    .sort((a, b) => Number(b.created_at || 0) - Number(a.created_at || 0)).slice(0, 20);
  $("jobsCount").textContent = String(jobs.length);
  if (!jobs.length) { const empty = document.createElement("p"); empty.className = "no-incidents"; empty.textContent = "Команды ещё не запускались"; list.append(empty); return; }
  for (const job of jobs) {
    const card = document.createElement("article"); card.className = "job-card";
    const heading = document.createElement("div"); heading.className = "job-heading";
    const title = document.createElement("strong"); title.textContent = jobState(job);
    const time = document.createElement("span"); time.textContent = timestamp(job.created_at);
    heading.append(title, time);
    const meta = document.createElement("p"); meta.textContent = `Задание ${String(job.id || "—")}${job.exit_code === null || job.exit_code === undefined ? "" : ` · код выхода ${job.exit_code}`}`;
    card.append(heading, meta);
    if (!job.transient_output && job.output !== null && job.output !== undefined && job.output !== "") {
      const output = document.createElement(isSealedOutput(job.output) ? "p" : "pre");
      output.className = isSealedOutput(job.output) ? "field-help" : "job-output";
      output.textContent = isSealedOutput(job.output) ? "Зашифрованный VPN-профиль. Для получения файла откройте раздел VPN в той же вкладке." : String(job.output);
      card.append(output);
    }
    list.append(card);
  }
}

function terminalApiPath(serverId, sessionId = null) {
  const base = `/api/v1/servers/${encodeURIComponent(serverId)}/terminal/sessions`;
  return sessionId ? `${base}/${encodeURIComponent(sessionId)}` : base;
}

function terminalServer(terminal = terminalClient) {
  const id = terminal.serverId ?? terminal.pendingStart?.serverId ?? terminal.targetServerId ?? state.selectedId;
  return state.servers.find((server) => String(server.id) === String(id));
}

function terminalSessionCurrent(terminal, sessionId, generation) {
  return terminal.sessionId === sessionId && terminal.pollGeneration === generation &&
    terminal.token === state.token && terminal.base === state.base && Boolean(state.token);
}

function renderTerminalTabs() {
  const list = $("terminalTabs");
  for (const terminal of terminalTabs.items) {
    if (!terminal.tabNode) {
      const item = document.createElement("div");
      item.setAttribute("role", "presentation");
      const select = document.createElement("button");
      select.type = "button";
      select.id = `terminal-tab-${terminal.id}`;
      select.className = "terminal-tab-select";
      select.setAttribute("role", "tab");
      select.setAttribute("aria-controls", "terminalScreen");
      const dot = document.createElement("span");
      dot.setAttribute("aria-hidden", "true");
      const title = document.createElement("span");
      title.className = "terminal-tab-title";
      select.append(dot, title);
      select.addEventListener("click", () => activateTerminalTab(terminal));
      select.addEventListener("keydown", (event) => {
        let index = terminalTabs.items.indexOf(terminal);
        if (event.key === "ArrowRight") index = (index + 1) % terminalTabs.items.length;
        else if (event.key === "ArrowLeft") index = (index - 1 + terminalTabs.items.length) % terminalTabs.items.length;
        else if (event.key === "Home") index = 0;
        else if (event.key === "End") index = terminalTabs.items.length - 1;
        else return;
        event.preventDefault();
        activateTerminalTab(terminalTabs.items[index], true);
      });
      const close = document.createElement("button");
      close.type = "button";
      close.className = "terminal-tab-close";
      close.textContent = "×";
      close.addEventListener("click", () => { void closeTerminalTab(terminal); });
      item.append(select, close);
      Object.assign(terminal, { tabNode: item, tabSelect: select, tabClose: close, tabDot: dot, tabTitle: title });
    }
    const item = terminal.tabNode, select = terminal.tabSelect, close = terminal.tabClose;
    item.className = `terminal-tab ${terminal === terminalClient ? "active" : ""}`;
    select.setAttribute("aria-selected", String(terminal === terminalClient));
    select.tabIndex = terminal === terminalClient ? 0 : -1;
    const name = terminalServer(terminal);
    const label = name ? String(name.name || name.id) : `Терминал ${terminal.id}`;
    select.setAttribute("aria-label", `${label}, ${terminalStatusName(terminal.status)}`);
    terminal.tabDot.className = `terminal-tab-dot ${terminal.status}`;
    terminal.tabTitle.textContent = label;
    close.setAttribute("aria-label", `Закрыть вкладку ${label}`);
    close.disabled = terminal.status === "closing";
  }
  if (list.children.length !== terminalTabs.items.length ||
      terminalTabs.items.some((terminal, index) => list.children[index] !== terminal.tabNode)) {
    list.replaceChildren(...terminalTabs.items.map((terminal) => terminal.tabNode));
  }
  const add = $("terminalAddTabButton");
  add.disabled = terminalTabs.items.length >= TERMINAL_TAB_LIMIT;
  add.title = add.disabled ? `Доступно не больше ${TERMINAL_TAB_LIMIT} вкладок` : "Открыть вкладку для выбранного сервера";
}

function terminalStatusName(status) {
  return { idle: "отключён", pending: "в очереди", starting: "запускается", active: "подключён",
    reconnecting: "восстанавливается", disconnected: "нет связи", closing: "закрывается", closed: "завершён" }[status] || "отключён";
}

function activateTerminalTab(terminal, focus = false) {
  if (!terminalTabs.items.includes(terminal)) return;
  $("terminalInput").value = "";
  $("terminalInput").type = "text";
  $("terminalInputVisibility").textContent = "Скрыть";
  $("terminalInputVisibility").setAttribute("aria-label", "Скрыть ввод");
  $("terminalInputVisibility").setAttribute("aria-pressed", "false");
  clearError($("terminalInputError"));
  terminalClient = terminal;
  for (const item of terminalTabs.items) if (item.screen) item.screen.hidden = item !== terminal;
  $("terminalScreen").setAttribute("aria-labelledby", `terminal-tab-${terminal.id}`);
  renderTerminalControls();
  if (state.view === "commands") setTimeout(fitTerminal, 0);
  if (focus) $("terminalTabs").querySelector?.('[role="tab"][aria-selected="true"]')?.focus();
}

function addTerminalTab() {
  if (terminalTabs.items.length >= TERMINAL_TAB_LIMIT) return;
  const terminal = newTerminalClient(terminalTabs.nextId++, state.selectedId);
  terminalTabs.items.push(terminal);
  activateTerminalTab(terminal, true);
}

async function closeTerminalTab(terminal) {
  if (!terminalTabs.items.includes(terminal) || terminal.status === "closing") return;
  if (!(await closeTerminalClient(terminal))) return;
  if (!terminalTabs.items.includes(terminal)) return;
  if (terminalTabs.items.length === 1) return;
  const index = terminalTabs.items.indexOf(terminal);
  terminalTabs.items.splice(index, 1);
  if (terminalClient === terminal) activateTerminalTab(terminalTabs.items[Math.max(0, index - 1)], true);
  else renderTerminalTabs();
}

function renderTerminalControls() {
  const terminal = terminalClient, server = terminalServer();
  const names = { idle: "Отключён", pending: "В очереди", starting: "Запускается", active: "Подключён",
    reconnecting: "Восстанавливаем", disconnected: "Нет связи", closing: "Закрывается", closed: "Завершён" };
  const badge = $("terminalStatusBadge");
  badge.textContent = names[terminal.status] || "Отключён";
  badge.className = `status-badge ${["disconnected", "closed"].includes(terminal.status) ? "offline" : terminal.status === "active" ? "" : "waiting"}`;
  const slowStart = ["pending", "starting"].includes(terminal.status) && terminal.pendingSince &&
    Date.now() - terminal.pendingSince > 30000;
  const note = slowStart ? "Agent не запустил PTY. Проверьте allow_remote_commands=true и allow_interactive_terminal=true на выбранном сервере." :
    terminal.reason || "Ввод и вывод доступны только в этой вкладке.";
  $("terminalTarget").textContent = server
    ? `${terminal.sessionId || terminal.pendingStart ? "Сессия сервера" : "Выбран сервер"}: ${String(server.name || server.id)}. ${note}`
    : "Выберите сервер с работающим Agent и разрешёнными командами.";
  const start = $("terminalStartButton");
  start.hidden = Boolean(terminal.sessionId && terminal.status !== "closed");
  start.textContent = terminal.pendingStart ? "Повторить открытие" : terminal.status === "closed" ? "Новая сессия" : "Открыть терминал";
  start.disabled = terminal.startInFlight || terminal.status === "closing" ||
    (!terminal.pendingStart && !Boolean(server?.online && server?.remote_commands_enabled));
  $("terminalReconnectButton").hidden = terminal.status !== "disconnected" || !terminal.sessionId;
  $("terminalCloseButton").hidden = !terminal.sessionId && !terminal.pendingStart;
  $("terminalCloseButton").disabled = terminal.status === "closing";
  for (const button of document.querySelectorAll("[data-terminal-key]")) {
    button.disabled = terminal.status !== "active";
  }
  const lineEnabled = terminal.status === "active" && Boolean(terminal.sessionId);
  $("terminalInput").disabled = !lineEnabled;
  $("terminalInputVisibility").disabled = !lineEnabled;
  $("terminalInputSend").disabled = !lineEnabled;
  if (terminal.status === "closed") $("terminalInput").value = "";
  if (terminal.error) showError($("terminalError"), terminal.error);
  else clearError($("terminalError"));
  renderTerminalTabs();
}

function bestEffortDeleteTerminalSession(base, token, serverId, sessionId) {
  if (!base || !token || !serverId || !sessionId) return;
  try {
    fetch(`${base}${terminalApiPath(serverId, sessionId)}`, { method: "DELETE",
      headers: { Authorization: `Bearer ${token}` }, cache: "no-store", keepalive: true }).catch(() => {});
  } catch { /* Hub also expires idle sessions. */ }
}

function resetTerminal(closeRemote = false, terminal = terminalClient, render = true) {
  const old = { base: terminal.base, token: terminal.token, serverId: terminal.serverId, sessionId: terminal.sessionId };
  terminal.pollGeneration++;
  terminal.pollAbort?.abort();
  terminal.pollAbort = null;
  if (terminal.inputTimer) clearTimeout(terminal.inputTimer);
  if (terminal.resizeTimer) clearTimeout(terminal.resizeTimer);
  terminal.resizeObserver?.disconnect();
  terminal.term?.dispose();
  if (terminal.screen?.remove) terminal.screen.remove();
  else if (terminalTabs.items.length === 1) $("terminalScreen").replaceChildren();
  if (terminal === terminalClient) {
    $("terminalInput").value = "";
    $("terminalInput").type = "text";
    $("terminalInputVisibility").textContent = "Скрыть";
    $("terminalInputVisibility").setAttribute("aria-label", "Скрыть ввод");
    $("terminalInputVisibility").setAttribute("aria-pressed", "false");
    clearError($("terminalInputError"));
  }
  Object.assign(terminal, { token: "", base: "", serverId: null, sessionId: null, status: "idle", reason: "", error: "",
    pendingStart: null, pendingSince: null, startInFlight: false, after: 0, nextSeq: 1, operations: [], sending: null,
    inputBuffer: "", inputTimer: null, pollAbort: null, term: null, fit: null, screen: null, resizeObserver: null, resizeTimer: null,
    cols: 80, rows: 24 });
  if (render) {
    if (terminal === terminalClient) renderTerminalControls();
    else renderTerminalTabs();
  }
  if (closeRemote) bestEffortDeleteTerminalSession(old.base, old.token, old.serverId, old.sessionId);
}

function resetAllTerminals(closeRemote = false) {
  const first = terminalTabs.items[0];
  for (const terminal of terminalTabs.items) resetTerminal(closeRemote, terminal, false);
  terminalTabs.items = [first];
  terminalClient = first;
  first.targetServerId = null;
  $("terminalScreen").replaceChildren();
}

function terminalPalette() {
  return document.documentElement?.dataset?.theme === "light"
    ? { background: "#eef4f1", foreground: "#18312d", cursor: "#17694c", selectionBackground: "#b9ddc9" }
    : { background: "#07151a", foreground: "#d4ebdf", cursor: "#80e1af", selectionBackground: "#31564e" };
}

function createTerminalScreen(terminalClientForTab = terminalClient) {
  if (terminalClientForTab.term) return;
  if (!globalThis.Terminal || !globalThis.FitAddon?.FitAddon) {
    throw new Error("Компонент терминала не загрузился. Обновите страницу.");
  }
  const client = terminalClientForTab;
  const screen = document.createElement("div");
  screen.className = "terminal-instance-screen";
  screen.hidden = client !== terminalClient;
  $("terminalScreen").append(screen);
  const terminal = new Terminal({ cursorBlink: true, scrollback: 3000, convertEol: false,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace", fontSize: 13,
    theme: terminalPalette() });
  const fit = new FitAddon.FitAddon();
  terminal.loadAddon(fit);
  terminal.open(screen);
  terminal.onData((data) => queueTerminalInputFor(client, data));
  client.term = terminal;
  client.fit = fit;
  client.screen = screen;
  if (globalThis.ResizeObserver) {
    client.resizeObserver = new ResizeObserver(() => {
      if (client.resizeTimer) clearTimeout(client.resizeTimer);
      client.resizeTimer = setTimeout(() => fitTerminalFor(client), 80);
    });
    client.resizeObserver.observe(screen);
  }
  fitTerminalFor(client);
  // xterm measures its cell size after the first paint. Fit again once those
  // measurements exist, especially when opening a terminal on a narrow phone.
  globalThis.requestAnimationFrame?.(() => fitTerminalFor(client));
}

function fitTerminal() {
  fitTerminalFor(terminalClient);
}

function fitTerminalFor(terminal) {
  if (terminal !== terminalClient || !terminal.term || state.view !== "commands") return;
  const screen = terminal.screen;
  if (screen.hidden || screen.getBoundingClientRect?.().width === 0) return;
  try { terminal.fit.fit(); }
  catch { return; }
  const cols = Math.max(20, Math.min(300, terminal.term.cols || 80));
  const rows = Math.max(10, Math.min(120, terminal.term.rows || 24));
  if (terminal.sessionId && (cols !== terminal.cols || rows !== terminal.rows)) {
    terminal.cols = cols; terminal.rows = rows;
    const last = terminal.operations.at(-1);
    if (last?.kind === "resize" && !last.seq) last.body = { cols, rows };
    else terminal.operations.push({ kind: "resize", body: { cols, rows }, seq: null });
    void drainTerminalOperationsFor(terminal);
  } else { terminal.cols = cols; terminal.rows = rows; }
}

async function startTerminal() {
  const terminal = terminalClient;
  if (terminal.startInFlight || (terminal.sessionId && terminal.status !== "closed")) return;
  if (terminal.status === "closed") resetTerminal(false, terminal);
  const selected = terminalServer(terminal);
  if (!terminal.pendingStart && !Boolean(selected?.online && selected?.remote_commands_enabled)) {
    terminal.error = "Выберите подключённый сервер с разрешёнными командами.";
    renderTerminalState(terminal);
    return;
  }
  if (!terminal.pendingStart && terminalTabs.items.some((other) => other !== terminal &&
      String(other.serverId ?? other.pendingStart?.serverId) === String(selected.id) &&
      (other.sessionId || other.pendingStart) && other.status !== "closed")) {
    terminal.error = "На этом сервере уже открыта другая вкладка терминала. Переключитесь на неё или закройте её.";
    renderTerminalState(terminal);
    return;
  }
  terminal.error = "";
  try { createTerminalScreen(terminal); }
  catch (error) { terminal.error = error.message; renderTerminalState(terminal); return; }
  const pending = terminal.pendingStart || {
    serverId: selected.id, token: state.token, base: state.base, key: crypto.randomUUID(),
    cols: terminal.cols || 80, rows: terminal.rows || 24,
  };
  terminal.pendingStart = pending;
  terminal.startInFlight = true;
  terminal.status = "starting";
  terminal.reason = "";
  renderTerminalState(terminal);
  try {
    const payload = await request(terminalApiPath(pending.serverId), { method: "POST",
      headers: { "Idempotency-Key": pending.key }, body: JSON.stringify({ cols: pending.cols, rows: pending.rows }) });
    const session = payload.session;
    if (terminal.pendingStart !== pending || state.token !== pending.token || state.base !== pending.base) {
      if (session?.id && String(session.server_id) === String(pending.serverId))
        bestEffortDeleteTerminalSession(pending.base, pending.token, pending.serverId, session.id);
      return;
    }
    if (!session?.id || String(session.server_id) !== String(pending.serverId)) throw new Error("Hub вернул неверную сессию терминала.");
    terminal.serverId = pending.serverId;
    terminal.sessionId = session.id;
    terminal.token = pending.token;
    terminal.base = pending.base;
    terminal.pendingStart = null;
    terminal.targetServerId = pending.serverId;
    terminal.status = ["pending", "starting", "active"].includes(session.state) ? session.state : "pending";
    terminal.pendingSince = Date.now();
    terminal.after = 0;
    terminal.nextSeq = 1;
    terminal.operations = [];
    renderTerminalState(terminal);
    if (terminal.cols !== pending.cols || terminal.rows !== pending.rows) {
      terminal.cols = pending.cols;
      terminal.rows = pending.rows;
      fitTerminalFor(terminal);
    }
    void pollTerminalFor(terminal);
  } catch (error) {
    if (terminal.pendingStart === pending && state.token === pending.token && state.base === pending.base) {
      terminal.status = "disconnected";
      terminal.reason = "Ответ о создании сессии не получен. Повтор использует тот же ключ.";
      terminal.error = error.message || "Не удалось открыть терминал.";
      renderTerminalState(terminal);
    }
  } finally {
    if (terminal.pendingStart === pending || terminal.sessionId) {
      terminal.startInFlight = false;
      renderTerminalState(terminal);
    }
  }
}

async function pollTerminal() {
  return pollTerminalFor(terminalClient);
}

function renderTerminalState(terminal) {
  if (terminal === terminalClient) renderTerminalControls();
  else renderTerminalTabs();
}

async function pollTerminalFor(terminal) {
  if (!terminal.sessionId || terminal.pollAbort) return;
  const sessionId = terminal.sessionId, generation = ++terminal.pollGeneration;
  const controller = new AbortController();
  terminal.pollAbort = controller;
  while (terminalSessionCurrent(terminal, sessionId, generation)) {
    try {
      const payload = await request(`${terminalApiPath(terminal.serverId, sessionId)}/events?after=${terminal.after}`,
        { signal: controller.signal, timeoutMs: 23000 });
      if (!terminalSessionCurrent(terminal, sessionId, generation)) break;
      if (!Array.isArray(payload.events) || !Number.isSafeInteger(payload.next_after) || payload.next_after < terminal.after ||
          !["pending", "starting", "active", "closed"].includes(payload.state)) throw new Error("Hub вернул неверное событие терминала.");
      for (const event of payload.events) {
        if (!terminalSessionCurrent(terminal, sessionId, generation)) break;
        if (event.type !== "output" || !Number.isSafeInteger(event.seq) || event.seq <= terminal.after ||
            event.seq > payload.next_after) throw new Error("Hub вернул неверный порядок вывода терминала.");
        const bytes = base64UrlDecode(event.data, null, 65536);
        terminal.term?.write(bytes);
        terminal.after = event.seq;
      }
      if (!terminalSessionCurrent(terminal, sessionId, generation)) break;
      terminal.after = payload.next_after;
      terminal.status = payload.state;
      if (payload.state === "active") terminal.pendingSince = null;
      terminal.reason = payload.state === "closed" ? terminalCloseReason(payload.reason, payload.exit_code) : "";
      terminal.error = "";
      renderTerminalState(terminal);
      if (payload.state === "closed") break;
      void drainTerminalOperationsFor(terminal);
    } catch (error) {
      if (!terminalSessionCurrent(terminal, sessionId, generation)) break;
      if ([403, 404, 409].includes(error.status)) {
        terminal.status = "closed";
        terminal.reason = error.status === 403 ? "Разрешение на терминал отозвано." :
          error.status === 409 ? "Вывод устарел; откройте новую сессию." : "Сессия больше не существует; откройте новую.";
      } else {
        terminal.status = "disconnected";
        terminal.reason = "Связь прервалась. Восстановление продолжит вывод с прежнего места.";
      }
      terminal.error = error.message || "Не удалось получить вывод терминала.";
      renderTerminalState(terminal);
      break;
    }
  }
  if (terminal.pollAbort === controller) terminal.pollAbort = null;
}

function terminalCloseReason(reason, exitCode) {
  const reasons = { process_exit: "Процесс завершился.", closed: "Сессия закрыта.",
    browser_idle: "Сессия закрыта после 90 секунд без связи с браузером.",
    time_limit: "Истекло время сессии (30 минут).", output_overflow: "Буфер вывода переполнен.",
    input_overflow: "Буфер ввода переполнен.", agent_start_timeout: "Агент не запустил терминал вовремя.",
    permission_revoked: "Разрешение на команды отозвано.", session_revoked: "Вход в Hub завершён.",
    output_cursor_lost: "Вывод устарел; откройте новую сессию.", control_cursor_lost: "Порядок ввода нарушен." };
  return `${reasons[reason] || "Сессия завершена."}${Number.isInteger(exitCode) ? ` Код выхода: ${exitCode}.` : ""}`;
}

function reconnectTerminal() {
  if (!terminalClient.sessionId || terminalClient.status !== "disconnected") return;
  terminalClient.status = "reconnecting";
  terminalClient.reason = "Проверяем состояние сессии и непрочитанный вывод.";
  terminalClient.error = "";
  renderTerminalControls();
  void pollTerminalFor(terminalClient);
}

function queueTerminalInput(data) {
  queueTerminalInputFor(terminalClient, data);
}

function queueTerminalInputFor(terminal, data) {
  if (terminal !== terminalClient || terminal.status !== "active" || !terminal.sessionId || typeof data !== "string" || !data) return;
  terminal.inputBuffer += data;
  if (terminal.inputTimer) clearTimeout(terminal.inputTimer);
  terminal.inputTimer = setTimeout(() => flushTerminalInputFor(terminal), 18);
  if (terminal.inputBuffer.length >= 3000) flushTerminalInputFor(terminal);
}

function flushTerminalInput() {
  flushTerminalInputFor(terminalClient);
}

function flushTerminalInputFor(terminal) {
  if (terminal.inputTimer) clearTimeout(terminal.inputTimer);
  terminal.inputTimer = null;
  if (!terminal.inputBuffer || !terminal.sessionId) return;
  const bytes = new TextEncoder().encode(terminal.inputBuffer);
  terminal.inputBuffer = "";
  for (let offset = 0; offset < bytes.length; offset += 4096) {
    terminal.operations.push({ kind: "input", body: { data: base64UrlEncode(bytes.subarray(offset, offset + 4096)) }, seq: null });
  }
  void drainTerminalOperationsFor(terminal);
}

async function drainTerminalOperations() {
  return drainTerminalOperationsFor(terminalClient);
}

async function drainTerminalOperationsFor(terminal) {
  if (terminal.sending || !terminal.sessionId || !["pending", "starting", "active"].includes(terminal.status)) return;
  const run = Symbol("terminal-send");
  terminal.sending = run;
  const sessionId = terminal.sessionId, token = terminal.token, base = terminal.base;
  try {
    while (terminal.operations.length && terminal.sessionId === sessionId && terminal.token === state.token &&
           terminal.base === state.base && ["pending", "starting", "active"].includes(terminal.status)) {
      const operation = terminal.operations[0];
      if (!operation.seq) operation.seq = terminal.nextSeq;
      const payload = await request(`${terminalApiPath(terminal.serverId, sessionId)}/${operation.kind}`, {
        method: "POST", body: JSON.stringify({ seq: operation.seq, ...operation.body }), timeoutMs: 16000,
      });
      if (terminal.sessionId !== sessionId || token !== state.token || base !== state.base ||
          !["pending", "starting", "active"].includes(terminal.status)) break;
      if (payload.accepted !== true || payload.next_seq !== operation.seq) throw new Error("Hub не подтвердил ввод терминала.");
      if (terminal.operations[0] !== operation) break;
      terminal.operations.shift();
      terminal.nextSeq++;
    }
  } catch (error) {
    if (terminal.sessionId === sessionId && token === state.token && base === state.base &&
        ["pending", "starting", "active"].includes(terminal.status)) {
      terminal.status = [403, 404, 409].includes(error.status) ? "closed" : "disconnected";
      terminal.reason = error.status === 403 ? "Разрешение на терминал отозвано." :
        error.status === 404 ? "Сессия больше не существует." :
          error.status === 409 ? "Нарушен порядок ввода; откройте новую сессию." :
            "Не удалось отправить ввод. При восстановлении повторится тот же пакет.";
      terminal.pollGeneration++;
      terminal.pollAbort?.abort();
      terminal.pollAbort = null;
      terminal.error = error.message || "Не удалось отправить ввод терминала.";
      renderTerminalState(terminal);
    }
  } finally { if (terminal.sending === run) terminal.sending = null; }
}

async function closeTerminal() {
  return closeTerminalClient(terminalClient);
}

async function closeTerminalClient(terminal) {
  if (terminal.status === "closing") return false;
  if (!terminal.sessionId) { resetTerminal(false, terminal); return true; }
  const sessionId = terminal.sessionId, token = terminal.token, base = terminal.base, serverId = terminal.serverId;
  terminal.status = "closing";
  terminal.error = "";
  terminal.inputBuffer = "";
  terminal.operations = [];
  if (terminal === terminalClient) {
    $("terminalInput").value = "";
    $("terminalInput").type = "text";
    $("terminalInputVisibility").textContent = "Скрыть";
    $("terminalInputVisibility").setAttribute("aria-label", "Скрыть ввод");
    $("terminalInputVisibility").setAttribute("aria-pressed", "false");
  }
  if (terminal.inputTimer) clearTimeout(terminal.inputTimer);
  terminal.inputTimer = null;
  terminal.pollGeneration++;
  terminal.pollAbort?.abort();
  terminal.pollAbort = null;
  renderTerminalState(terminal);
  try {
    await request(terminalApiPath(serverId, sessionId), { method: "DELETE", timeoutMs: 12000 });
    if (terminal.sessionId === sessionId && token === state.token && base === state.base) resetTerminal(false, terminal);
    return true;
  } catch (error) {
    if (error.status === 404) {
      if (terminal.sessionId === sessionId && token === state.token && base === state.base) resetTerminal(false, terminal);
      return true;
    }
    if (state.token === token && state.base === base && terminal.sessionId === sessionId) {
      terminal.status = "disconnected";
      terminal.reason = "Закрытие не подтверждено. Повторите закрытие сессии.";
      terminal.error = error.message || "Не удалось закрыть терминал.";
      renderTerminalState(terminal);
    }
    return false;
  }
}

function sendTerminalKey(key) {
  if (key === "focus") { terminalClient.term?.focus(); return; }
  const bytes = { esc: "\x1b", tab: "\t", "ctrl-c": "\x03", "ctrl-d": "\x04", "ctrl-l": "\x0c", "ctrl-z": "\x1a",
    up: "\x1b[A", down: "\x1b[B", left: "\x1b[D", right: "\x1b[C", home: "\x1b[H", end: "\x1b[F",
    pageup: "\x1b[5~", pagedown: "\x1b[6~", enter: "\r" };
  if (Object.hasOwn(bytes, key)) queueTerminalInput(bytes[key]);
  terminalClient.term?.focus();
}

function sendTerminalLine(event) {
  event.preventDefault();
  clearError($("terminalInputError"));
  const field = $("terminalInput");
  if (terminalClient.status !== "active" || !terminalClient.sessionId) {
    showError($("terminalInputError"), "Сначала откройте терминал и дождитесь подключения.");
    return;
  }
  const line = field.value;
  if (!line || /[\r\n\0]/.test(line)) {
    showError($("terminalInputError"), "Введите одну строку без переносов. Пустой Enter доступен в ряду клавиш ниже.");
    return;
  }
  field.value = "";
  queueTerminalInput(`${line}\r`);
  field.focus?.();
}

function toggleTerminalLineVisibility() {
  const field = $("terminalInput"), button = $("terminalInputVisibility");
  field.type = field.type === "password" ? "text" : "password";
  const hidden = field.type === "password";
  button.textContent = hidden ? "Показать" : "Скрыть";
  button.setAttribute("aria-label", hidden ? "Показать ввод" : "Скрыть ввод");
  button.setAttribute("aria-pressed", String(hidden));
  field.focus?.();
}

function rejectMultilineTerminalPaste(event) {
  if (/[\r\n\0]/.test(event.clipboardData?.getData("text") || "")) {
    event.preventDefault();
    showError($("terminalInputError"), "Вставьте одну строку. Несколько команд можно отправить по одной.");
  } else clearError($("terminalInputError"));
}

function renderEvents() {
  const items = state.incidents.filter((item) => String(item.server_id) === String(state.selectedId))
    .sort((a, b) => Number(b.updated_at || 0) - Number(a.updated_at || 0));
  $("eventsCount").textContent = String(items.filter((item) => item.state === "firing").length);
  $("navIncidentCount").textContent = $("eventsCount").textContent;
  const list = $("eventsList"); list.replaceChildren();
  if (!items.length) { const empty = document.createElement("p"); empty.className = "no-incidents"; empty.textContent = "Событий пока нет"; list.append(empty); return; }
  for (const incident of items) {
    const card = document.createElement("article"); card.className = `incident ${incident.state === "resolved" ? "resolved" : ""} ${incident.kind === "high_root_inodes" && incident.state === "resolved" ? "inode-closed" : ""}`;
    const dot = document.createElement("span"); dot.className = "incident-dot"; dot.setAttribute("aria-hidden", "true");
    const body = document.createElement("div");
    const title = document.createElement("h3"); title.textContent = incidentLabel(incident);
    const detail = document.createElement("p"); detail.textContent = [incidentTimeline(incident), incidentTlsDetail(incident), incidentInodeDetail(incident),
      incident.acknowledged_at ? `подтверждено ${timestamp(incident.acknowledged_at)}` : ""].filter(Boolean).join(" · ");
    body.append(title, detail); card.append(dot, body);
    if (incident.state === "firing" && !incident.acknowledged_at && hubCanAcknowledge()) {
      const button = document.createElement("button"); button.type = "button"; button.className = "secondary-button incident-action"; button.textContent = "Подтвердить";
      button.addEventListener("click", () => acknowledgeIncident(incident.id, button)); card.append(button);
    }
    list.append(card);
  }
}

function renderAudit() {
  const list = $("auditList"); list.replaceChildren();
  const events = state.audit.slice(0, 50);
  $("auditCount").textContent = String(events.length);
  if (!events.length) { const empty = document.createElement("p"); empty.className = "no-incidents"; empty.textContent = "Действий пока нет"; list.append(empty); return; }
  const labels = {
    session_login: "Вход в Hub", server_created: "Добавлен сервер", agent_token_rotated: "Токен агента изменён",
    incident_acknowledged: "Подтверждено событие", remote_commands_enabled: "Команды разрешены в Hub",
    remote_commands_disabled: "Команды отключены в Hub", command_requested: "Запрошена команда",
    command_queued: "Команда поставлена в очередь", command_delivered: "Команда передана агенту",
    journal_requested: "Запрошен журнал службы",
    command_completed: "Команда завершена", queued_web_jobs_cancelled: "Ожидающие команды отменены",
    bot_binding_upsert: "Изменена роль Telegram", bot_binding_removed: "Удалена роль Telegram",
    bot_commands_cancelled: "Команды Telegram отменены", password_changed: "Пароль администратора изменён",
  };
  for (const event of events) {
    const card = document.createElement("div"); card.className = "audit-row";
    const main = document.createElement("strong"); main.textContent = labels[event.action] || String(event.action || "Действие");
    const meta = document.createElement("span"); meta.textContent = `${timestamp(event.at)} · ${String(event.actor || "система")}${event.server_id ? ` · ${String(event.server_id).slice(0, 8)}` : ""}`;
    card.append(main, meta); list.append(card);
  }
}

function vpnTarget() {
  return state.servers.find((server) => String(server.id) === String(state.vpnTargetId));
}

function vpnInventoryContext(targetId, extra = {}) {
  if (targetId === VPN_HUB_HOST) return { kind: "hub", ...extra };
  const server = state.servers.find((item) => String(item.id) === String(targetId));
  return server ? { kind: "server", name: String(server.name || server.id), ...extra } : { kind: "none", ...extra };
}

async function refreshVpnInventory(current) {
  const targetId = state.vpnTargetId;
  const active = () => current() && String(state.vpnTargetId) === String(targetId) && state.view === "vpn";
  if (state.vpnInventoryTargetId !== targetId) {
    state.vpnInventoryTargetId = targetId;
    state.vpn = { source_status: "loading" };
    renderVpn(state.vpn, vpnInventoryContext(targetId));
  }
  if (!targetId) {
    state.vpn = { source_status: "unavailable" };
    renderVpn(state.vpn, vpnInventoryContext(targetId));
    return;
  }
  try {
    const hubHost = targetId === VPN_HUB_HOST;
    const path = hubHost ? "/api/v1/vpn" : `/api/v1/servers/${encodeURIComponent(targetId)}/vpn`;
    const payload = await request(path);
    if (!active()) return;
    let context = vpnInventoryContext(targetId);
    if (!hubHost) {
      if (String(payload?.server_id) !== String(targetId) ||
          !["ok", "stale", "unavailable"].includes(payload?.freshness) ||
          (payload.received_at !== null && (!Number.isSafeInteger(payload.received_at) || payload.received_at < 0)) ||
          !payload.vpn || typeof payload.vpn !== "object" || Array.isArray(payload.vpn)) {
        throw new Error("Центр мониторинга вернул неверную VPN-сводку сервера.");
      }
      context = vpnInventoryContext(targetId, { freshness: payload.freshness, receivedAt: payload.received_at });
    }
    state.vpn = payload.vpn || { source_status: "unavailable" };
    renderVpn(state.vpn, context);
  } catch (error) {
    if (!active()) return;
    const availability = error.status === 403 ? "denied" : error.status === 404 ? "unsupported" : "error";
    state.vpn = { source_status: availability === "error" ? "error" : "unavailable" };
    renderVpn(state.vpn, vpnInventoryContext(targetId, { availability }));
    if (availability === "error") throw error;
  }
}

function vpnTargetReady() {
  const server = vpnTarget();
  return hubCanAdmin(server ?? null) && Boolean(server?.online && server?.remote_commands_enabled);
}

function renderVpnControls(source) {
  const targetSelect = $("vpnTargetServer");
  const previousTarget = state.vpnTargetId;
  if (!(previousTarget === VPN_HUB_HOST && hubCanGlobalAdmin()) &&
      !state.servers.some((server) => String(server.id) === String(previousTarget))) {
    state.vpnTargetId = state.servers.find((server) => String(server.id) === String(state.selectedId))?.id ??
      state.servers[0]?.id ?? (hubCanGlobalAdmin() ? VPN_HUB_HOST : null);
  }
  targetSelect.replaceChildren();
  if (hubCanGlobalAdmin()) {
    const option = document.createElement("option"); option.value = VPN_HUB_HOST;
    option.textContent = "Хост панели (Hub)";
    targetSelect.append(option);
  }
  for (const server of state.servers) {
    const option = document.createElement("option"); option.value = server.id;
    option.textContent = String(server.name || server.id);
    targetSelect.append(option);
  }
  targetSelect.disabled = !hubCanGlobalAdmin() && !state.servers.length;
  targetSelect.value = state.vpnTargetId === null ? "" : String(state.vpnTargetId);
  const server = vpnTarget();
  $("vpnTargetStatus").textContent = state.vpnTargetId === VPN_HUB_HOST ?
    "Показан хост панели. Для операций выберите сервер с Agent." :
    !server ? "Добавьте сервер с Agent, чтобы получать VPN-сводку." :
    !hubCanAdmin(server) ? "Сводка доступна для просмотра. Для операций нужен доступ администратора." :
    !server.online ? "Выбранный Agent сейчас не на связи." :
    !server.remote_commands_enabled ? "Разрешите команды для этого сервера в разделе «Команды»." :
    "Операции доступны. Состояние в сводке обновляется таймером раз в 30 секунд.";
  $("vpnCreateButton").disabled = !vpnTargetReady();
  $("vpnInstanceButton").disabled = !vpnTargetReady();
  $("vpnClientButton").disabled = !vpnTargetReady();
  $("vpnExportButton").disabled = !vpnTargetReady();
  applyHubPermissions();
  globalThis.amneziaTargetChanged?.();
}

function renderVpnActionJob() {
  const panel = $("vpnActionJobPanel"), job = state.vpnActionJob;
  panel.hidden = !state.vpnActionJobId;
  if (!state.vpnActionJobId) return;
  $("vpnActionJobState").textContent = job ? jobState(job) : "В очереди";
  const exportRequest = activeSealedExport?.jobId === state.vpnActionJobId && sealedSessionCurrent(activeSealedExport)
    ? activeSealedExport : null;
  const sealed = Boolean(exportRequest) || isSealedOutput(job?.output);
  $("vpnActionJobText").textContent = `Задание ${state.vpnActionJobId}. После завершения обновите сводку; таймер собирает её каждые 30 секунд.`;
  const output = $("vpnActionJobOutput");
  output.textContent = sealed ? "" : job?.output ? String(job.output) : "";
  output.hidden = !output.textContent;
  const profileStatus = $("vpnProfileStatus");
  profileStatus.textContent = "";
  $("vpnProfileDownload").hidden = true;
  $("vpnProfileShare").hidden = true;
  if (!sealed) return;
  if (!exportRequest) {
    profileStatus.textContent = "Ключ этой выдачи отсутствует в текущей вкладке. Запросите профиль ещё раз.";
    return;
  }
  if (job?.state === "succeeded" && exportRequest.status === "pending") {
    void prepareSealedDownload(exportRequest, job);
    return;
  }
  if (exportRequest.status === "ready") {
    profileStatus.textContent = "Профиль расшифрован только в этой вкладке. Сохраните его на своё устройство.";
    $("vpnProfileDownload").hidden = false;
    try { $("vpnProfileShare").hidden = !navigator.canShare?.({ files: [exportRequest.file] }); }
    catch { $("vpnProfileShare").hidden = true; }
  } else if (exportRequest.status === "decrypting") {
    profileStatus.textContent = "Расшифровываем профиль на этом устройстве…";
  } else if (exportRequest.status === "failed") {
    profileStatus.textContent = "Не удалось подготовить файл. Запросите профиль ещё раз.";
  } else if (job && !["queued", "delivered", "succeeded"].includes(job.state)) {
    profileStatus.textContent = "Выдача профиля завершилась с ошибкой. Запросите его ещё раз.";
  } else {
    profileStatus.textContent = "Ожидаем зашифрованный профиль от сервера. Не закрывайте эту вкладку.";
  }
}

function renderManagedVpn(source, availability = null) {
  renderVpnControls(source);
  const status = ["loading", "ok", "stale", "error", "unavailable"].includes(source?.source_status) ? source.source_status : "unavailable";
  const labels = { loading: "Обновляем...", ok: "Данные актуальны", stale: "Данные устарели", error: "Ошибка сбора", unavailable: "Нет данных" };
  const descriptions = {
    loading: "Запрашиваем состояние управляемого WireGuard.",
    ok: "Состояние собственных WireGuard-инстансов SovaGrid. Клиентские ключи и адреса здесь не показываются.",
    stale: "Последний снимок WireGuard устарел. Состояние могло измениться.",
    error: "Состояние управляемого WireGuard недоступно. Сервисы Amnezia показаны отдельно.",
    unavailable: "Адаптер управляемого WireGuard ещё не прислал снимок.",
  };
  const badge = $("managedSourceBadge");
  badge.textContent = labels[status];
  badge.className = `status-badge vpn-status-${status}`;
  $("managedSourceText").textContent = availability === "denied" ?
    "Нет доступа к сводке этого сервера." : availability === "unsupported" ?
      "Обновите Hub, чтобы получать сводку управляемого WireGuard." : descriptions[status];
  const available = status === "ok" || status === "stale";
  const instances = available && Array.isArray(source?.instances) ? source.instances : [];
  $("managedCount").textContent = available ? String(instances.length) : "—";
  $("managedActive").textContent = available ? String(instances.filter((item) => item.state === "active").length) : "—";
  $("managedError").textContent = available ? String(instances.filter((item) => item.state === "error").length) : "—";
  const list = $("managedInstancesList"); list.replaceChildren();
  if (!instances.length) {
    const empty = document.createElement("p"); empty.className = "no-incidents";
    empty.textContent = available ? "Управляемых WireGuard-инстансов пока нет" : "Список инстансов пока недоступен";
    list.append(empty);
    return;
  }
  const states = { active: "Активен", stopped: "Остановлен", error: "Требует проверки" };
  for (const instance of instances) {
    const card = document.createElement("article"); card.className = "vpn-service-card";
    const heading = document.createElement("div"); heading.className = "vpn-service-heading";
    const name = document.createElement("h3"); name.textContent = String(instance.name || "Инстанс");
    const stateLabel = document.createElement("span"); stateLabel.textContent = states[instance.state] || "Неизвестно";
    stateLabel.className = `vpn-service-state ${instance.state === "active" ? "running" : instance.state === "error" ? "problem" : "waiting"}`;
    heading.append(name, stateLabel);
    const iface = document.createElement("p"); iface.textContent = String(instance.interface || "");
    const grid = document.createElement("div"); grid.className = "vpn-service-meta";
    for (const [label, value] of [
      ["UDP-порт", instance.port],
      ["Подсеть", instance.subnet],
      ["Клиентов", instance.client_count],
    ]) {
      const item = document.createElement("div");
      const title = document.createElement("span"); title.textContent = label;
      const detail = document.createElement("strong"); detail.textContent = value === null || value === undefined ? "—" : String(value);
      item.append(title, detail); grid.append(item);
    }
    card.append(heading, iface, grid); list.append(card);
  }
}

function renderAmneziaDetails(source, availability = null) {
  const status = ["ok", "stale", "error", "unavailable"].includes(source?.source_status)
    ? source.source_status : "unavailable";
  const labels = { ok: "Данные актуальны", stale: "Данные устарели", error: "Ошибка сбора", unavailable: "Нет данных" };
  $("amneziaDetailBadge").textContent = labels[status];
  $("amneziaDetailBadge").className = `status-badge vpn-status-${status}`;
  const descriptions = {
    ok: "Состояние интерфейсов, процессов, клиентских записей и активности. Настройки и ключи не публикуются.",
    stale: "Последний подробный снимок устарел; состояние протоколов могло измениться.",
    error: "Подробная проверка Amnezia недоступна. Сводка Docker показана отдельно.",
    unavailable: "Подробная проверка Amnezia ещё не настроена на сервере.",
  };
  $("amneziaDetailText").textContent = availability === "denied" ?
    "Нет доступа к подробной сводке этого сервера." : availability === "unsupported" ?
      "Обновите Hub, чтобы получать подробную сводку Amnezia." : descriptions[status];
  const list = $("amneziaDetailList"); list.replaceChildren();
  const services = ["ok", "stale"].includes(status) && Array.isArray(source?.services) ? source.services : [];
  if (!services.length) {
    const empty = document.createElement("p"); empty.className = "no-incidents";
    empty.textContent = status === "ok" || status === "stale"
      ? "Детальных проверок пока нет" : "Детали протоколов недоступны";
    list.append(empty);
    return;
  }
  const names = { "amnezia-awg2": "AmneziaWG", "amnezia-wireguard": "WireGuard", "amnezia-xray": "Xray VLESS" };
  const states = {
    ready: "Работает", container_down: "Контейнер остановлен",
    identity_mismatch: "Контейнер изменён", interface_down: "Интерфейс отключён",
    registry_drift: "Расхождение клиентов", runtime_drift: "Расхождение интерфейса",
    process_down: "Процесс остановлен", error: "Проверка не удалась",
  };
  for (const service of services) {
    const card = document.createElement("article"); card.className = "vpn-service-card";
    const heading = document.createElement("div"); heading.className = "vpn-service-heading";
    const title = document.createElement("h3"); title.textContent = names[service.name] || "Amnezia";
    const state = document.createElement("span"); state.textContent = states[service.status] || "Неизвестно";
    state.className = `vpn-service-state ${service.status === "ready" ? "running" : "problem"}`;
    heading.append(title, state);
    const grid = document.createElement("div"); grid.className = "vpn-service-meta";
    const fields = [
      ["Клиентских записей", service.configured_clients],
      ["В интерфейсе", service.runtime_clients],
    ];
    if (service.name === "amnezia-xray") {
      fields.push(["API управления", service.api_enabled === true ? "Включён" : "Выключен"]);
      fields.push(["Статистика Xray", service.stats_enabled === true ? "Включена" : "Выключена"]);
    } else {
      fields.push(["Активны за 3 минуты", service.active_last_3m]);
      fields.push(["Последний handshake", service.latest_handshake_at ? timestamp(service.latest_handshake_at) : "—"]);
      fields.push(["Получено", service.received_bytes === undefined ? null : bytes(service.received_bytes)]);
      fields.push(["Отправлено", service.sent_bytes === undefined ? null : bytes(service.sent_bytes)]);
    }
    for (const [label, value] of fields) {
      const item = document.createElement("div");
      const caption = document.createElement("span"); caption.textContent = label;
      const detail = document.createElement("strong"); detail.textContent = value === null || value === undefined ? "—" : String(value);
      item.append(caption, detail); grid.append(item);
    }
    card.append(heading, grid); list.append(card);
  }
}

function renderVpn(snapshot, source = { kind: "hub" }) {
  // Hub receipt time decides freshness for remote Agents. Agent clocks can be
  // skewed, and a stale source must never be displayed as current.
  let shown = snapshot;
  if (source.kind === "server" && source.freshness === "unavailable") {
    shown = { source_status: "unavailable" };
  } else if (source.kind === "server" && source.freshness === "stale") {
    const staleIfOk = (item) => item?.source_status === "ok" ? { ...item, source_status: "stale" } : item;
    shown = { ...snapshot, source_status: snapshot?.source_status === "ok" ? "stale" : snapshot?.source_status,
      managed: staleIfOk(snapshot?.managed), amnezia_details: staleIfOk(snapshot?.amnezia_details) };
  }
  renderManagedVpn(shown?.managed || (shown?.source_status === "loading" ? { source_status: "loading" } : null), source.availability);
  renderAmneziaDetails(shown?.amnezia_details, source.availability);
  const status = ["loading", "ok", "stale", "error", "unavailable"].includes(shown?.source_status) ? shown.source_status : "unavailable";
  const services = Array.isArray(shown?.services) ? shown.services : [];
  const labels = { loading: "Обновляем...", ok: "Данные актуальны", stale: "Данные устарели", error: "Ошибка сбора", unavailable: "Нет данных" };
  const remote = source.kind === "server";
  const descriptions = remote ? {
    loading: "Запрашиваем VPN-сводку выбранного сервера.",
    ok: "Состояние обнаруженных сервисов Amnezia на выбранном сервере.",
    stale: "Последняя VPN-сводка этого сервера устарела. Состояние сервисов могло измениться.",
    error: "Agent не смог получить состояние Docker на выбранном сервере.",
    unavailable: "Agent ещё не прислал VPN-сводку для выбранного сервера.",
  } : {
    loading: "Запрашиваем снимок состояния сервисов Amnezia на хосте панели.",
    ok: "Состояние обнаруженных сервисов Amnezia на хосте центра мониторинга.",
    stale: "Последний снимок устарел. Состояние сервисов могло измениться.",
    error: "Адаптер не смог получить состояние Docker. Дождитесь следующего снимка и обновите страницу.",
    unavailable: "Адаптер VPN ещё не настроен или не прислал первый снимок.",
  };
  const badge = $("vpnSourceBadge");
  badge.textContent = source.availability === "denied" ? "Нет доступа" :
    source.availability === "unsupported" ? "Нужен новый Hub" : labels[status];
  badge.className = `status-badge vpn-status-${status}`;
  $("vpnSourceLocation").textContent = remote ? `Источник: ${source.name}` :
    source.kind === "hub" ? "Источник: хост панели (Hub)" : "Источник: сервер не выбран";
  $("vpnSourceText").textContent = source.availability === "denied" ?
    "Нет доступа к VPN-сводке выбранного сервера. Выберите доступный сервер." :
    source.availability === "unsupported" ?
      "Эта версия Hub ещё не поддерживает VPN-сводку выбранного источника. Обновите Hub." :
      source.availability === "error" ?
        "Не удалось получить VPN-сводку от Hub. Попробуйте обновить страницу." :
        source.kind === "none" ? "Добавьте сервер с Agent или выберите хост панели." : descriptions[status];
  $("vpnSnapshotTime").textContent = remote ?
    (source.receivedAt !== null && source.receivedAt !== undefined
      ? `Получено центром: ${timestamp(source.receivedAt)}${source.freshness === "stale" ? " · Данные устарели" : ""}`
      : "Снимок с сервера ещё не получен") :
    shown?.collected_at ? `Снимок: ${timestamp(shown.collected_at)}` : "Снимок ещё не получен";
  const available = status === "ok" || status === "stale";
  const detected = services.filter((item) => item.state !== "absent");
  $("vpnTotal").textContent = available ? String(detected.length) : "—";
  $("vpnRunning").textContent = available ? String(detected.filter((item) => item.state === "running").length) : "—";
  $("vpnUnhealthy").textContent = available ? String(detected.filter((item) => item.health === "unhealthy").length) : "—";
  $("vpnServicesCount").textContent = available ? String(detected.length) : "—";
  const list = $("vpnServicesList"); list.replaceChildren();
  if (!available || !detected.length) {
    const empty = document.createElement("p"); empty.className = "no-incidents";
    empty.textContent = available ? "Сервисы Amnezia не обнаружены" : "Список сервисов пока недоступен";
    list.append(empty);
    return;
  }
  const states = { created: "Создан", restarting: "Перезапускается", running: "Работает", removing: "Удаляется", paused: "Приостановлен", exited: "Остановлен", dead: "Не работает", absent: "Отсутствует", unknown: "Неизвестно", identity_mismatch: "Несоответствие контейнера" };
  const health = { healthy: "Исправен", unhealthy: "Ошибка проверки", starting: "Запускается", not_reported: "Проверка не настроена", unknown: "Неизвестно" };
  for (const service of detected) {
    const card = document.createElement("article"); card.className = "vpn-service-card";
    const heading = document.createElement("div"); heading.className = "vpn-service-heading";
    const name = document.createElement("h3"); name.textContent = String(service.service || service.name || "Сервис");
    const stateLabel = document.createElement("span"); stateLabel.textContent = states[service.state] || "Неизвестно";
    stateLabel.className = `vpn-service-state ${service.state === "running" ? "running" : service.state === "exited" || service.state === "dead" || service.state === "identity_mismatch" ? "problem" : "waiting"}`;
    heading.append(name, stateLabel);
    const meta = document.createElement("p"); meta.textContent = String(service.name || "");
    const grid = document.createElement("div"); grid.className = "vpn-service-meta";
    const healthItem = document.createElement("div");
    const healthTitle = document.createElement("span"); healthTitle.textContent = "Проверка";
    const healthValue = document.createElement("strong"); healthValue.textContent = health[service.health] || "Неизвестно";
    healthItem.append(healthTitle, healthValue);
    const portsItem = document.createElement("div");
    const portsTitle = document.createElement("span"); portsTitle.textContent = "Опубликованные порты";
    const portsValue = document.createElement("strong");
    const ports = Array.isArray(service.published_ports) ? service.published_ports : [];
    portsValue.textContent = ports.length ? ports.map((port) => `${port.port}/${port.protocol}`).join(", ") : "Нет";
    portsItem.append(portsTitle, portsValue);
    grid.append(healthItem, portsItem);
    card.append(heading, meta, grid); list.append(card);
  }
}

async function acknowledgeIncident(id, button) {
  if (!hubCanAcknowledge()) return;
  button.disabled = true;
  try { await request(`/api/v1/incidents/${encodeURIComponent(id)}/ack`, { method: "POST", body: "{}" }); await refresh(); }
  catch (error) { showError($("globalError"), error.message || "Не удалось подтвердить событие."); button.disabled = false; }
}

async function toggleCommands() {
  const server = selectedServer();
  if (!server) return;
  const enabled = !Boolean(server.remote_commands_enabled);
  if (enabled && !window.confirm(`Разрешить постановку команд для «${server.name}»? Агент также требует отдельного локального разрешения.`)) return;
  const button = $("commandPermissionButton"); button.disabled = true;
  try {
    await request(`/api/v1/servers/${encodeURIComponent(server.id)}/commands`, { method: "POST", body: JSON.stringify({ enabled }) });
    await refresh();
  } catch (error) { showError($("globalError"), error.message || "Не удалось изменить доступ к командам."); }
  finally { button.disabled = false; }
}

function prepareCommand(event) {
  event.preventDefault();
  clearError($("commandError"));
  const server = selectedServer();
  const command = $("commandInput").value.trim();
  if (!server || !server.online || !server.remote_commands_enabled) { showError($("commandError"), "Сервер должен быть на связи, а команды — разрешены в Hub."); return; }
  if (!command || new TextEncoder().encode(command).length > 2048) { showError($("commandError"), "Введите команду длиной до 2048 байт."); return; }
  let commandKey;
  try { commandKey = crypto.randomUUID(); }
  catch { showError($("commandError"), "Не удалось создать ключ операции. Откройте панель через HTTPS или localhost."); return; }
  state.pendingCommand = command;
  state.pendingServerId = server.id;
  state.pendingCommandKey = commandKey;
  $("confirmCommandServer").textContent = `Сервер: ${String(server.name || server.id)}`;
  $("confirmCommandText").textContent = command;
  clearError($("confirmCommandError"));
  $("confirmCommandDialog").showModal();
}

async function runCommand() {
  if (state.commandSubmitting) return;
  const server = selectedServer();
  const command = state.pendingCommand;
  if (!server || !command || !state.pendingCommandKey || String(server.id) !== String(state.pendingServerId)) {
    showError($("confirmCommandError"), "Выбранный сервер изменился. Закройте окно и проверьте команду заново.");
    return;
  }
  if (!server.remote_commands_enabled || !server.online) {
    showError($("confirmCommandError"), "Сервер недоступен или выполнение команд отключено. Проверьте состояние сервера.");
    return;
  }
  state.commandSubmitting = true;
  const commandKey = state.pendingCommandKey, sessionToken = state.token, sessionBase = state.base;
  state.submittingCommandKey = commandKey;
  const currentSubmission = () => state.submittingCommandKey === commandKey && state.token === sessionToken && state.base === sessionBase;
  $("runCommandButton").disabled = true;
  $("cancelCommandButton").disabled = true;
  let queued = false;
  try {
    await request(`/api/v1/servers/${encodeURIComponent(server.id)}/jobs`, {
      method: "POST",
      headers: { "Idempotency-Key": commandKey },
      body: JSON.stringify({ command }),
    });
    if (!currentSubmission()) return;
    queued = true;
    state.pendingCommand = "";
    state.pendingServerId = null;
    state.pendingCommandKey = null;
    $("commandInput").value = "";
    $("confirmCommandText").textContent = "";
    $("confirmCommandDialog").close();
  } catch (error) {
    if (!currentSubmission()) return;
    const uncertain = error.status === undefined && Boolean(state.token);
    const message = uncertain
      ? "Ответ на отправку не получен. Команда могла попасть в очередь. Проверьте задания; повторное нажатие «Выполнить» использует тот же ключ и не создаст вторую команду."
      : error.message || "Не удалось отправить команду.";
    if ($("confirmCommandDialog").open) showError($("confirmCommandError"), message);
    else if (state.token) showError($("globalError"), message);
    if (uncertain) void refresh();
  } finally {
    if (state.submittingCommandKey === commandKey) {
      state.commandSubmitting = false;
      state.submittingCommandKey = null;
      $("runCommandButton").disabled = false;
      $("cancelCommandButton").disabled = false;
    }
  }
  if (queued) await refresh();
}

const vpnActionTitles = {
  create: "Подготовить инстанс", activate: "Запустить WireGuard",
  "add-client": "Добавить клиента", "revoke-client": "Отозвать клиента",
  "sealed-export": "Получить защищённый профиль", remove: "Удалить инстанс",
};

function prepareVpnAction(payload, sealedContext = null) {
  sealedPrepareSeq++;
  clearError($("vpnCreateError")); clearError($("vpnClientError")); clearError($("vpnActionError"));
  const server = vpnTarget();
  if (!server || !vpnTargetReady()) {
    showError($("globalError"), "Для VPN-операции нужен подключённый сервер с разрешёнными командами.");
    return;
  }
  if (!vpnActionTitles[payload?.action] || !/^[a-z][a-z0-9-]{1,31}$/.test(payload.name || "")) {
    showError($("globalError"), "Проверьте имя и тип VPN-операции.");
    return;
  }
  if (payload.action === "sealed-export" && (!sealedContext?.privateKey ||
      sealedContext.name !== payload.name || sealedContext.client !== payload.client ||
      sealedContext.route !== (payload.route || "split") ||
      sealedContext.publicKey !== payload.public_key ||
      String(sealedContext.serverId) !== String(server.id) ||
      sealedContext.token !== state.token || sealedContext.base !== state.base)) {
    showError($("globalError"), "Ключ защищённой выдачи устарел. Запросите профиль заново.");
    return;
  }
  let key;
  try { key = crypto.randomUUID(); }
  catch { showError($("globalError"), "Не удалось создать ключ операции. Откройте панель через HTTPS или localhost."); return; }
  pendingSealedExport = sealedContext ? { ...sealedContext, requestKey: key } : null;
  state.vpnPending = { payload, serverId: server.id, key };
  $("vpnActionTitle").textContent = vpnActionTitles[payload.action];
  $("vpnActionSummary").textContent = payload.action === "create"
    ? `${payload.name} · UDP ${payload.port} · ${payload.subnet} · ${payload.endpoint}`
    : payload.client ? `${payload.name} · клиент ${payload.client}${payload.action === "sealed-export" ?
      payload.route === "full" ? " · весь трафик через VPN" : " · только подсеть VPN" : ""}` : payload.name;
  $("vpnActionServer").textContent = `Сервер: ${String(server.name || server.id)}`;
  $("vpnRemoveConfirmation").hidden = payload.action !== "remove";
  $("vpnRemoveName").value = "";
  $("vpnActionConfirm").disabled = payload.action === "remove";
  $("vpnActionDialog").showModal();
}

async function prepareVpnExport(event) {
  event.preventDefault();
  clearError($("vpnExportError"));
  const name = $("vpnExportInstance").value.trim(), client = $("vpnExportClient").value.trim();
  const route = $("vpnExportRoute").value || "split";
  if (!/^[a-z][a-z0-9-]{1,31}$/.test(name) || !/^[a-z][a-z0-9_-]{0,31}$/.test(client)) {
    showError($("vpnExportError"), "Проверьте инстанс и имя клиента.");
    return;
  }
  if (!["split", "full"].includes(route)) {
    showError($("vpnExportError"), "Выберите маршрут для профиля."); return;
  }
  if (!vpnTargetReady()) {
    showError($("vpnExportError"), "Выбранный Agent недоступен или операции запрещены.");
    return;
  }
  if (globalThis.isSecureContext !== true || !globalThis.crypto?.subtle) {
    showError($("vpnExportError"), "Защищённая выдача доступна через HTTPS или localhost в современном браузере.");
    return;
  }
  const generation = ++sealedPrepareSeq;
  const serverId = vpnTarget().id, token = state.token, base = state.base;
  $("vpnExportButton").disabled = true;
  try {
    const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const rawPublic = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    if (generation !== sealedPrepareSeq || token !== state.token || base !== state.base ||
        String(serverId) !== String(state.vpnTargetId)) return;
    if (rawPublic.length !== 65 || rawPublic[0] !== 4) throw new Error("Неверный публичный ключ.");
    const publicKey = base64UrlEncode(rawPublic);
    prepareVpnAction({ action: "sealed-export", name, client, public_key: publicKey,
      ...(route === "full" ? { route } : {}) },
    { privateKey: pair.privateKey, publicKey, name, client, route, serverId, token, base });
  } catch {
    if (generation === sealedPrepareSeq) showError($("vpnExportError"), "Не удалось создать ключ выдачи. Попробуйте обновить страницу.");
  } finally {
    if (token === state.token && base === state.base) $("vpnExportButton").disabled = !vpnTargetReady();
  }
}

function prepareVpnCreate(event) {
  event.preventDefault();
  const name = $("vpnCreateName").value.trim(), port = Number($("vpnCreatePort").value);
  const subnet = $("vpnCreateSubnet").value.trim(), endpoint = $("vpnCreateEndpoint").value.trim();
  if (!/^[a-z][a-z0-9-]{1,31}$/.test(name) || !Number.isInteger(port) || port < 1024 || port > 65535 || !subnet || !endpoint) {
    showError($("vpnCreateError"), "Проверьте имя, UDP-порт, подсеть и адрес сервера.");
    return;
  }
  prepareVpnAction({ action: "create", name, port, subnet, endpoint });
}

function prepareVpnClient(event) {
  event.preventDefault();
  const action = $("vpnClientAction").value, name = $("vpnClientInstance").value,
    client = $("vpnClientName").value.trim();
  if (!["add-client", "revoke-client"].includes(action) || !/^[a-z][a-z0-9-]{1,31}$/.test(name) || !/^[a-z][a-z0-9_-]{0,31}$/.test(client)) {
    showError($("vpnClientError"), "Проверьте инстанс и имя клиента.");
    return;
  }
  prepareVpnAction({ action, name, client });
}

function prepareVpnInstance(event) {
  event.preventDefault();
  clearError($("vpnInstanceError"));
  const action = $("vpnInstanceAction").value, name = $("vpnInstanceName").value.trim();
  if (!["activate", "remove"].includes(action) || !/^[a-z][a-z0-9-]{1,31}$/.test(name)) {
    showError($("vpnInstanceError"), "Проверьте операцию и имя инстанса.");
    return;
  }
  prepareVpnAction(action === "remove" ? { action, name, confirm_name: name } : { action, name });
}

async function submitVpnAction() {
  const pending = state.vpnPending;
  if (!pending || state.vpnSubmittingKey) return;
  const server = vpnTarget();
  if (!server || String(server.id) !== String(pending.serverId) || !vpnTargetReady()) {
    showError($("vpnActionError"), "Сервер изменился или недоступен. Закройте окно и проверьте операцию заново.");
    return;
  }
  if (pending.payload.action === "remove" && $("vpnRemoveName").value !== pending.payload.name) {
    showError($("vpnActionError"), "Введите точное имя инстанса для удаления.");
    return;
  }
  if (pending.payload.action === "sealed-export" &&
      (!pendingSealedExport || pendingSealedExport.requestKey !== pending.key)) {
    showError($("vpnActionError"), "Ключ этой выдачи потерян. Закройте окно и запросите профиль снова.");
    return;
  }
  const token = state.token, base = state.base, key = pending.key;
  state.vpnSubmittingKey = key;
  $("vpnActionConfirm").disabled = true;
  $("vpnActionCancel").disabled = true;
  const current = () => state.vpnSubmittingKey === key && state.token === token && state.base === base;
  let queued = false;
  try {
    const result = await request(`/api/v1/servers/${encodeURIComponent(server.id)}/vpn/actions`, {
      method: "POST", headers: { "Idempotency-Key": key }, body: JSON.stringify(pending.payload),
    });
    if (!current()) return;
    if (!result.job?.id) throw new Error("Задание поставлено в очередь, но его ID не получен. Проверьте журнал заданий.");
    queued = true;
    state.vpnActionJobId = result.job.id;
    state.vpnActionJob = result.job;
    if (pending.payload.action === "sealed-export") {
      activeSealedExport = { ...pendingSealedExport, jobId: result.job.id, status: "pending", file: null };
      pendingSealedExport = null;
    } else activeSealedExport = null;
    renderVpnActionJob();
    state.vpnPending = null;
    $("vpnActionDialog").close();
    if (pending.payload.action === "create") $("vpnCreateName").value = "";
    if (["add-client", "revoke-client"].includes(pending.payload.action)) $("vpnClientName").value = "";
    if (pending.payload.action === "sealed-export") {
      $("vpnExportInstance").value = "";
      $("vpnExportClient").value = "";
      $("vpnExportRoute").value = "split";
    }
  } catch (error) {
    if (!current()) return;
    const uncertain = error.status === undefined && Boolean(state.token);
    showError($("vpnActionError"), uncertain
      ? "Ответ не получен. Операция могла попасть в очередь; повторное нажатие использует тот же ключ и не создаст вторую. Проверьте задания и снимок VPN."
      : error.message || "Не удалось поставить VPN-операцию в очередь.");
    if (uncertain) void refresh();
  } finally {
    if (state.vpnSubmittingKey === key) {
      state.vpnSubmittingKey = null;
      $("vpnActionCancel").disabled = false;
      $("vpnActionConfirm").disabled = pending.payload.action === "remove" && $("vpnRemoveName").value !== pending.payload.name;
    }
  }
  if (queued) await refresh();
}

function nativeProfileBridge() {
  try {
    const origin = new URL(globalThis.location?.origin);
    if (!["http:", "https:"].includes(origin.protocol) || !isLoopback(origin)) return null;
  } catch { return null; }
  const android = globalThis.sovagridNativeProfile;
  if (typeof android?.postMessage === "function") return android;
  const apple = globalThis.webkit?.messageHandlers?.sovagridNativeProfile;
  return typeof apple?.postMessage === "function" ? apple : null;
}

async function downloadVpnProfile() {
  const exportRequest = activeSealedExport;
  if (!exportRequest || !sealedSessionCurrent(exportRequest) || exportRequest.status !== "ready" || !exportRequest.file) return;
  const bridge = nativeProfileBridge();
  if (bridge) {
    if (exportRequest.nativeSaving) return;
    exportRequest.nativeSaving = true;
    let bytes;
    try {
      const { name, client, file } = exportRequest;
      const filename = `${name}-${client}.conf`;
      if (!/^[a-z][a-z0-9-]{1,31}$/.test(name) || !/^[a-z][a-z0-9_-]{0,31}$/.test(client) ||
          file.name !== filename || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > 16384) {
        throw new Error("Получен неверный VPN-профиль.");
      }
      bytes = new Uint8Array(await file.arrayBuffer());
      if (!sealedSessionCurrent(exportRequest)) return;
      if (bytes.length !== file.size) throw new Error("Получен неверный VPN-профиль.");
      // The native host receives plaintext only after this explicit click and
      // validates this canonical, unpadded encoding again before saving.
      bridge.postMessage(JSON.stringify({ version: 1, filename, data: base64UrlEncode(bytes) }));
      if (sealedSessionCurrent(exportRequest)) {
        $("vpnProfileStatus").textContent = "Запрос на сохранение передан приложению. Выберите место для файла .conf.";
      }
    } catch {
      if (sealedSessionCurrent(exportRequest)) {
        $("vpnProfileStatus").textContent = "Не удалось открыть сохранение профиля в приложении. Попробуйте ещё раз.";
      }
    } finally {
      bytes?.fill(0);
      exportRequest.nativeSaving = false;
    }
    return;
  }
  const url = URL.createObjectURL(exportRequest.file);
  sealedDownloadUrls.add(url);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = exportRequest.file.name;
  anchor.hidden = true;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => {
    if (sealedDownloadUrls.delete(url)) URL.revokeObjectURL(url);
  }, 60000);
}

async function shareVpnProfile() {
  const exportRequest = activeSealedExport;
  if (!exportRequest || !sealedSessionCurrent(exportRequest) || exportRequest.status !== "ready" || !exportRequest.file) return;
  try {
    if (!navigator.canShare?.({ files: [exportRequest.file] })) return;
    await navigator.share({ files: [exportRequest.file], title: "Профиль WireGuard" });
  } catch (error) {
    if (error?.name !== "AbortError" && sealedSessionCurrent(exportRequest)) {
      $("vpnProfileStatus").textContent = "Не удалось поделиться файлом. Используйте кнопку «Скачать .conf».";
    }
  }
}

async function addServer(event) {
  event.preventDefault();
  clearError($("addServerError"));
  $("confirmAddButton").disabled = true;
  try {
    const payload = await request("/api/v1/servers", { method: "POST", body: JSON.stringify({ name: $("newServerName").value.trim() }) });
    if (!payload.id || !payload.agent_token) throw new Error("Сервер создан, но ID или токен агента не получен.");
    $("addServerDialog").close();
    $("newServerName").value = "";
    $("serverId").textContent = payload.id;
    $("agentToken").textContent = payload.agent_token;
    $("tokenDialog").showModal();
    state.selectedId = payload.server?.id ?? payload.id ?? state.selectedId;
    await refresh();
  } catch (error) { showError($("addServerError"), error.message || "Не удалось добавить сервер."); }
  finally { $("confirmAddButton").disabled = false; }
}

const serverSetup = { seq: 0, busy: false, phase: null, controllers: new Set(), mode: "ssh",
  reviewed: null, changedPin: false, kind: null, jobs: [], recovery: null, job: null, pollTimer: null };
const serverSetupFingerprintPattern = /^SHA256:[A-Za-z0-9+/]{43}$/;
const serverSetupUsernamePattern = /^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/;
const serverSetupKinds = {
  missing: ["SovaGrid не обнаружен", "Ubuntu доступна. Проверка ничего не установила и не добавила в панель. Ниже можно подготовить Agent."],
  managed: ["Найдена управляемая установка", "На Ubuntu обнаружена установка SovaGrid. Проверьте её принадлежность и подключение отдельно; этот запрос не добавил сервер в панель."],
  agent_only: ["Найден отдельный Agent", "На Ubuntu обнаружен Agent без полной установки Hub. Для подключения к этой панели потребуется отдельная регистрация."],
  conflict: ["Обнаружена конфликтующая установка", "На сервере есть неполные или несовместимые признаки SovaGrid. Ничего не изменено; проверьте его вручную."],
  unsupported: ["Система не поддерживается", "Удалённая система не распознана как поддерживаемая Ubuntu. Установка здесь не предлагается."],
  unknown: ["Состояние не удалось определить", "Данных недостаточно для надёжного вывода. Возможно, у SSH-пользователя нет root или sudo без запроса пароля. Ничего не изменено."],
};
function serverSetupAllowed() {
  return Boolean(state.token && state.user?.role === "admin" && state.access?.unrestricted_admin === true &&
    state.base === location.origin && (location.protocol === "https:" ||
      (location.protocol === "http:" && isLoopback(location))));
}
function serverSetupReason() {
  if (!state.token || state.user?.role !== "admin" || state.access?.unrestricted_admin !== true)
    return "Для SSH-проверки войдите администратором с доступом ко всем серверам.";
  if (state.base !== location.origin)
    return "Откройте панель напрямую на HTTPS-адресе этого Hub: SSH-данные нельзя передать через другой адрес Hub.";
  if (!serverSetupAllowed())
    return "Откройте панель по HTTPS или через локальный SSH-туннель. На обычном HTTP SSH-пароль и ключ передавать нельзя.";
  return "";
}
function serverSetupPinName(host, port) { return `sovagrid.target-ssh-host-key:${location.origin}:${host}:${port}`; }
function serverSetupPin(host, port) {
  try { return localStorage.getItem(serverSetupPinName(host, port)); } catch { return null; }
}
function serverSetupSavePin(host, port, fingerprint) {
  try { localStorage.setItem(serverSetupPinName(host, port), fingerprint); } catch { /* Private browsing may disable storage. */ }
}
function serverSetupClearSecrets() {
  $("serverSetupPassword").value = "";
  $("serverSetupPrivateKey").value = "";
  $("serverSetupPassphrase").value = "";
}
function serverSetupClearError() { $("serverSetupError").textContent = ""; $("serverSetupError").hidden = true; }
function serverSetupError(message) { $("serverSetupError").textContent = message; $("serverSetupError").hidden = false; }
function serverSetupPhaseName(phase) {
  return ({ prepared: "Пакет подготовлен", transport_ready: "Настроен защищённый канал",
    registered: "Сервер зарегистрирован", active: "Agent запущен" })[phase] || "Проверяем состояние";
}
function serverSetupRenderJobs() {
  const pending = serverSetup.jobs.filter((row) => row?.recoverable === true);
  const select = $("serverSetupRecoverySelect");
  const previous = serverSetup.recovery?.request_id || "";
  if (!pending.length) {
    select.replaceChildren?.();
    select.value = "";
    serverSetup.recovery = null;
    $("serverSetupRecovery").hidden = true;
    $("serverSetupRecoveryChoice").textContent = "";
    return;
  }
  const prompt = document.createElement("option");
  prompt.value = "";
  prompt.textContent = "Выберите установку";
  const options = pending.map((row) => {
    const option = document.createElement("option");
    option.value = row.request_id;
    option.textContent = `${row.name} · ${serverSetupPhaseName(row.phase)} · ${row.request_id.slice(0, 8)}`;
    return option;
  });
  select.replaceChildren(prompt, ...options);
  if (pending.some((row) => row.request_id === previous)) select.value = previous;
  else { select.value = ""; serverSetup.recovery = null; }
  $("serverSetupRecovery").hidden = pending.length === 0;
  $("serverSetupRecoveryChoice").textContent = serverSetup.recovery ?
    `Выбрана «${serverSetup.recovery.name}». Введите тот же адрес и SSH-пользователя, затем сверьте ключ.` : "";
}
function serverSetupRenderJob() {
  const job = serverSetup.job;
  $("serverSetupJobReview").hidden = !job;
  if (!job) return;
  $("serverSetupJobName").textContent = job.name || "—";
  $("serverSetupJobUbuntu").textContent = job.platform?.ubuntu_version || "—";
  $("serverSetupJobHubFingerprint").textContent = job.hub_fingerprint || "—";
  $("serverSetupJobSource").textContent = job.source_commits?.["sovagrid-agent"]?.slice(0, 12) || "—";
  $("serverSetupJobId").textContent = job.request_id;
  $("serverSetupJobStatus").textContent = job.phase === "active" ?
    "Agent установлен и подключён. Сервер появится в списке после обновления панели." :
    job.cleanup_required ? "Установка требует проверки и очистки перед повторной попыткой." :
    `${serverSetupPhaseName(job.phase)}. Временный пакет на сервере уже записан; подтвердите запуск Agent или очистите подготовку.`;
  $("serverSetupApplyConfirm").disabled = serverSetup.busy || job.phase === "active" || job.cleanup_required;
  $("serverSetupApplyButton").disabled = serverSetup.busy || job.phase === "active" ||
    job.cleanup_required || !$("serverSetupApplyConfirm").checked;
  $("serverSetupApplyButton").textContent = serverSetup.phase === "apply" ? "Устанавливаем Agent…" : "4. Установить и подключить Agent";
  $("serverSetupCleanupButton").disabled = serverSetup.busy || job.phase === "active";
}
function serverSetupRender() {
  const ssh = serverSetup.mode === "ssh";
  $("serverSetupSshPanel").hidden = !ssh;
  $("serverSetupAgentPanel").hidden = ssh;
  $("serverSetupSshTab").setAttribute("aria-selected", String(ssh));
  $("serverSetupAgentTab").setAttribute("aria-selected", String(!ssh));
  const reason = serverSetupReason();
  $("serverSetupNotice").textContent = reason;
  $("serverSetupNotice").hidden = !reason;
  $("serverSetupReview").hidden = !serverSetup.reviewed;
  $("serverSetupStatusForm").hidden = !ssh || !serverSetup.reviewed || Boolean(serverSetup.job);
  $("serverSetupChangedKey").hidden = !serverSetup.changedPin;
  $("serverSetupReplaceKey").hidden = !serverSetup.changedPin;
  $("serverSetupKeyFields").hidden = !$("serverSetupAuthKey").checked;
  $("serverSetupPasswordFields").hidden = $("serverSetupAuthKey").checked;
  $("serverSetupInspect").disabled = serverSetup.busy || Boolean(serverSetup.job) || !serverSetupAllowed();
  $("serverSetupInspect").textContent = serverSetup.phase === "inspect" ? "Проверяем SSH-ключ…" : "1. Проверить SSH-ключ";
  $("serverSetupStatusButton").disabled = serverSetup.busy || Boolean(serverSetup.job) || !serverSetupAllowed() ||
    !serverSetup.reviewed || serverSetup.changedPin || !$("serverSetupTrust").checked;
  $("serverSetupStatusButton").textContent = serverSetup.phase === "status" ?
    "Проверяем состояние…" : "2. Проверить состояние без изменений";
  $("serverSetupInstallPanel").hidden = !ssh || !serverSetup.reviewed || serverSetup.changedPin ||
    !$("serverSetupTrust").checked || (!serverSetup.recovery && serverSetup.kind !== "missing") || Boolean(serverSetup.job);
  $("serverSetupInstallFields").hidden = Boolean(serverSetup.recovery);
  $("serverSetupInstallHeading").textContent = serverSetup.recovery ? "Возобновить установку" : "Установить Agent на этот сервер";
  $("serverSetupInstallIntro").textContent = serverSetup.recovery ?
    "Введите SSH-данные заново. Будет проверена прежняя запись, ключ сервера и временный пакет. Agent не запустится до отдельного подтверждения." :
    "Для установки снова введите SSH-пароль или выберите ключ выше. Сначала проверим связь без изменений, затем запишем временный пакет для отдельного подтверждения.";
  $("serverSetupPrepareButton").disabled = serverSetup.busy || !serverSetupAllowed() || !serverSetup.reviewed ||
    serverSetup.changedPin || !$("serverSetupTrust").checked;
  $("serverSetupPrepareButton").textContent = serverSetup.phase === "prepare" || serverSetup.phase === "resume" ?
    "Подготавливаем установку…" : serverSetup.recovery ? "Проверить и восстановить" : "3. Проверить связь и подготовить установку";
  $("serverSetupReloadJobs").disabled = serverSetup.busy;
  $("serverSetupRecoverySelect").disabled = serverSetup.busy || Boolean(serverSetup.job);
  $("serverSetupInterruptButton").hidden = !["prepare", "resume", "apply", "cleanup"].includes(serverSetup.phase);
  serverSetupRenderJob();
  for (const id of ["serverSetupHost", "serverSetupPort", "serverSetupUsername", "serverSetupAuthPassword",
    "serverSetupAuthKey", "serverSetupPassword", "serverSetupPrivateKey", "serverSetupPassphrase"]) {
    $(id).disabled = serverSetup.busy || Boolean(serverSetup.job);
  }
  for (const id of ["serverSetupInstallName", "serverSetupHubHost", "serverSetupHubPort", "serverSetupLocalPort"])
    $(id).disabled = serverSetup.busy;
}
function serverSetupInvalidate() {
  serverSetup.seq++;
  for (const controller of serverSetup.controllers) controller.abort();
  serverSetup.controllers.clear();
  if (serverSetup.pollTimer) clearInterval(serverSetup.pollTimer);
  serverSetup.pollTimer = null;
  serverSetup.busy = false;
  serverSetup.phase = null;
  serverSetup.reviewed = null;
  serverSetup.changedPin = false;
  serverSetup.kind = null;
  serverSetup.job = null;
  $("serverSetupApplyConfirm").checked = false;
  $("serverSetupTrust").checked = false;
  $("serverSetupResult").hidden = true;
  serverSetupClearSecrets();
  serverSetupClearError();
  serverSetupRender();
}
function serverSetupReset() {
  serverSetupInvalidate();
  serverSetup.mode = "ssh";
  serverSetup.jobs = [];
  serverSetup.recovery = null;
  serverSetupRenderJobs();
  $("serverSetupHost").value = "";
  $("serverSetupPort").value = "22";
  $("serverSetupUsername").value = "";
  $("serverSetupAuthPassword").checked = true;
  $("serverSetupAuthKey").checked = false;
  $("serverSetupInstallName").value = "";
  $("serverSetupHubHost").value = /^(?:[0-9.]+|[0-9a-f:]+)$/i.test(location.hostname) && !isLoopback(location) ? location.hostname : "";
  $("serverSetupHubPort").value = "22";
  $("serverSetupLocalPort").value = "18767";
  serverSetupRender();
}
function serverSetupMode(mode) {
  if (serverSetup.busy) return;
  serverSetupInvalidate();
  serverSetup.mode = mode;
  serverSetupRender();
  (mode === "ssh" ? $("serverSetupHost") : $("newServerName")).focus?.();
}
function serverSetupTarget() {
  const host = $("serverSetupHost").value.trim();
  const rawPort = $("serverSetupPort").value;
  if (!host || host.length > 253 || !/^[A-Za-z0-9.:-]+$/.test(host) || host.includes("..") ||
      !/^[0-9]{1,5}$/.test(rawPort)) throw new Error("Укажите корректный адрес и порт SSH (1–65535). Для IPv6 не добавляйте скобки.");
  const port = Number(rawPort);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("Порт SSH должен быть от 1 до 65535.");
  return { host: host.toLowerCase(), port };
}
function serverSetupExplain(error) {
  const code = error?.message;
  if (code === "AUTH_FAILED") return "SSH не принял пароль или ключ. Проверьте данные и попробуйте снова.";
  if (code === "AUTH_REQUIRED") return "Сеанс панели истёк. Войдите заново и повторите проверку.";
  if (code === "ADMIN_FORBIDDEN") return "Нужен администратор панели с доступом ко всем серверам.";
  if (code === "HOST_KEY_CHANGED") return "Ключ SSH изменился после сверки. Не повторяйте вход, пока не проверите новый отпечаток независимо.";
  if (code === "UNSUPPORTED_AUTH_METHOD") return "Этот способ SSH-входа, включая двухфакторный запрос, пока не поддерживается.";
  if (code === "INVALID_INPUT") return "Проверьте адрес, порт, пользователя и способ SSH-входа.";
  if (code === "RATE_LIMIT") return "Слишком много попыток. Подождите минуту.";
  if (code === "BUSY") return "SSH-шлюз занят. Попробуйте позже.";
  if (code === "STATUS_UNAVAILABLE") return "SSH-вход выполнен, но прочитать состояние Ubuntu не удалось.";
  if (code === "SSH_UNAVAILABLE") return "SSH-сервер не ответил. Проверьте адрес, порт и доступность из сети Hub.";
  if (code === "INSTALLER_UNAVAILABLE") return "Установщик Agent на этом Hub пока недоступен. Обновите серверную часть и повторите запрос.";
  if (code === "ROUTE_UNAVAILABLE") return "Не удалось проверить путь от нового сервера до SSH-порта Hub.";
  if (code === "RECOVERY_REQUIRED") return "Есть незавершённая установка. Выберите её в списке выше, восстановите или очистите.";
  if (code === "RESUME_REQUIRED") return "Нужен повторный SSH-вход для этой установки. Выберите запись выше и введите данные заново.";
  if (code === "HOST_KEY_MISMATCH" || code === "TARGET_CHANGED") return "Сервер или его SSH-ключ не совпал с исходной установкой. Проверьте выбранную запись и адрес.";
  if (code === "STALE_REVISION") return "Состояние установки изменилось. Обновите запись перед следующим действием.";
  if (code === "PREPARE_UNCERTAIN" || code === "APPLY_UNCERTAIN" ||
      code === "RESUME_UNCERTAIN" || code === "CLEANUP_UNCERTAIN")
    return "Связь прервалась, состояние установки неясно. Обновите список и восстановите запись по ID; не начинайте новую установку.";
  if (code === "SOURCE_UNTRUSTED") return "Проверенный пакет на Hub недоступен или изменился. Обновите серверную часть.";
  if (code === "ARCHIVE_UNSAFE") return "Закрытая история установок на Hub повреждена или имеет неверные права. Проверьте её через Connect до следующей установки.";
  if (code === "ARCHIVE_FULL") return "История установок на Hub заполнена. Сохраните резервную копию и обратитесь к администратору хоста.";
  if (error?.status === 404 || error?.status === 502) return "Проверка второго сервера ещё не включена на этом Hub. Обновите серверную часть.";
  if (code === "SSH_TIMEOUT") return "SSH-сервер не ответил вовремя.";
  return "Не удалось выполнить запрос. Обновите состояние установки перед повтором.";
}
async function serverSetupApi(path, value, timeoutMs, seq) {
  if (!serverSetupAllowed() || !$("addServerDialog").open || seq !== serverSetup.seq) throw new Error("STALE_REQUEST");
  const controller = new AbortController();
  serverSetup.controllers.add(controller);
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const body = JSON.stringify(value);
  for (const key of ["password", "private_key", "passphrase"]) if (Object.hasOwn(value, key)) value[key] = "";
  try {
    const response = await fetch(path, { method: "POST", credentials: "omit", cache: "no-store",
      redirect: "error", referrerPolicy: "no-referrer",
      headers: { "Content-Type": "application/json", Accept: "application/json", Authorization: `Bearer ${state.token}` },
      body, signal: controller.signal });
    let payload;
    try { payload = await response.json(); } catch { throw new Error("INVALID_RESPONSE"); }
    if (!response.ok) {
      const failure = new Error(typeof payload?.error === "string" ? payload.error : "SSH_UNAVAILABLE");
      failure.status = response.status;
      if (typeof payload?.request_id === "string") failure.requestId = payload.request_id;
      throw failure;
    }
    return payload;
  } catch (error) {
    if (error.name === "AbortError") throw new Error("SSH_TIMEOUT");
    throw error;
  } finally { clearTimeout(timer); serverSetup.controllers.delete(controller); }
}
async function serverSetupInspect() {
  if (serverSetup.busy) return;
  if (!serverSetupAllowed()) { serverSetupError(serverSetupReason()); return; }
  let target;
  try { target = serverSetupTarget(); } catch (error) { serverSetupError(error.message); return; }
  serverSetupInvalidate();
  const seq = serverSetup.seq;
  const token = state.token;
  serverSetup.busy = true;
  serverSetup.phase = "inspect";
  serverSetupRender();
  try {
    const reply = await serverSetupApi("/api/v1/browser-ssh/target-host-key", target, 12000, seq);
    if (seq !== serverSetup.seq || !$("addServerDialog").open || !serverSetupAllowed() || state.token !== token) return;
    if (reply?.protocol !== 1 || reply.scope !== "entered_target" || reply.reverify_required !== true ||
        reply.host !== target.host || reply.port !== target.port ||
        typeof reply.key_type !== "string" || !/^[A-Za-z0-9@._-]{4,96}$/.test(reply.key_type) ||
        typeof reply.fingerprint !== "string" || !serverSetupFingerprintPattern.test(reply.fingerprint)) {
      throw new Error("INVALID_RESPONSE");
    }
    serverSetup.reviewed = { ...target, fingerprint: reply.fingerprint };
    $("serverSetupReviewedHost").textContent = target.host.includes(":") ?
      `[${target.host}]:${target.port}` : `${target.host}:${target.port}`;
    $("serverSetupFingerprint").textContent = reply.fingerprint;
    $("serverSetupKeyType").textContent = `Алгоритм: ${reply.key_type}`;
    serverSetup.changedPin = Boolean(serverSetupPin(target.host, target.port) &&
      serverSetupPin(target.host, target.port) !== reply.fingerprint);
    if (serverSetup.changedPin) serverSetupError("Закреплённый SSH-ключ изменился. Сверьте новый отпечаток независимо.");
  } catch (error) {
    if (seq === serverSetup.seq) serverSetupError(serverSetupExplain(error));
  } finally {
    if (seq === serverSetup.seq) { serverSetup.busy = false; serverSetup.phase = null; serverSetupRender(); }
  }
}
function serverSetupCredentialsChanged(clearOther = false) {
  if (serverSetup.kind !== "missing" && !serverSetup.recovery) $("serverSetupResult").hidden = true;
  if (serverSetup.busy) { serverSetupInvalidate(); return; }
  if (clearOther) serverSetupClearSecrets();
  serverSetupRender();
}
async function serverSetupStatus(event) {
  event.preventDefault();
  if (serverSetup.busy || !serverSetupAllowed() || !serverSetup.reviewed || serverSetup.changedPin ||
      !$("serverSetupTrust").checked || !$("addServerDialog").open) return;
  const reviewed = { ...serverSetup.reviewed };
  let target;
  try { target = serverSetupTarget(); } catch (error) { serverSetupError(error.message); return; }
  if (target.host !== reviewed.host || target.port !== reviewed.port) {
    serverSetupInvalidate(); serverSetupError("Адрес или порт изменились. Сверьте SSH-ключ заново."); return;
  }
  const username = $("serverSetupUsername").value.trim();
  const method = $("serverSetupAuthKey").checked ? "private_key" : "password";
  if (!serverSetupUsernamePattern.test(username)) {
    serverSetupError("Введите имя пользователя SSH без пробелов и специальных символов."); return;
  }
  const file = method === "private_key" ? $("serverSetupPrivateKey").files?.[0] : null;
  if (method === "private_key" && (!file || file.size < 1 || file.size > 65536)) {
    serverSetupError("Выберите файл приватного ключа размером до 64 КиБ."); return;
  }
  const priorPin = serverSetupPin(reviewed.host, reviewed.port);
  const seq = ++serverSetup.seq;
  const token = state.token;
  serverSetup.busy = true;
  serverSetup.phase = "status";
  serverSetupClearError();
  $("serverSetupResult").hidden = true;
  serverSetupRender();
  let password = "", private_key = "", passphrase = "";
  try {
    if (method === "private_key") {
      try { private_key = await file.text(); } catch { throw new Error("FILE_READ_FAILED"); }
      passphrase = $("serverSetupPassphrase").value;
    } else password = $("serverSetupPassword").value;
    if (seq !== serverSetup.seq || !serverSetupAllowed() || !$("addServerDialog").open ||
        state.token !== token || serverSetupPin(reviewed.host, reviewed.port) !== priorPin ||
        !$("serverSetupTrust").checked || serverSetup.changedPin ||
        $("serverSetupUsername").value.trim() !== username ||
        (($("serverSetupAuthKey").checked ? "private_key" : "password") !== method) ||
        (method === "private_key" && $("serverSetupPrivateKey").files?.[0] !== file)) {
      throw new Error("STALE_REQUEST");
    }
    if (method === "password" && (!password || password.length > 1024)) {
      throw new Error("PASSWORD_INVALID");
    }
    if (passphrase.length > 1024) throw new Error("PASSPHRASE_INVALID");
    serverSetupClearSecrets();
    const payload = { host: reviewed.host, port: reviewed.port, username, method,
      fingerprint: reviewed.fingerprint, password, private_key, passphrase };
    password = private_key = passphrase = "";
    const reply = await serverSetupApi("/api/v1/browser-ssh/target-status", payload, 30000, seq);
    if (seq !== serverSetup.seq || !$("addServerDialog").open || !serverSetupAllowed() ||
        state.token !== token || serverSetupPin(reviewed.host, reviewed.port) !== priorPin) return;
    if (reply?.protocol !== 1 || reply.scope !== "entered_target" || reply.host !== reviewed.host ||
        reply.port !== reviewed.port || reply.host_key_fingerprint !== reviewed.fingerprint ||
        !Object.hasOwn(serverSetupKinds, reply.kind)) throw new Error("INVALID_RESPONSE");
    serverSetupSavePin(reviewed.host, reviewed.port, reviewed.fingerprint);
    serverSetup.kind = reply.kind;
    if (reply.kind === "missing" && !$("serverSetupInstallName").value)
      $("serverSetupInstallName").value = reviewed.host.slice(0, 80);
    $("serverSetupResultTitle").textContent = serverSetupKinds[reply.kind][0];
    $("serverSetupResultText").textContent = serverSetupKinds[reply.kind][1];
    $("serverSetupResult").hidden = false;
  } catch (error) {
    if (seq === serverSetup.seq) {
      if (error.message === "HOST_KEY_CHANGED") serverSetupInvalidate();
      serverSetupError(
        error.message === "FILE_READ_FAILED" ? "Не удалось прочитать файл приватного ключа." :
        error.message === "PASSWORD_INVALID" ? "Введите пароль SSH длиной до 1024 символов." :
        error.message === "PASSPHRASE_INVALID" ? "Парольная фраза ключа слишком длинная." :
        error.message === "STALE_REQUEST" ? "Параметры проверки изменились. Сверьте SSH-ключ и попробуйте снова." :
        serverSetupExplain(error));
    }
  } finally {
    password = private_key = passphrase = "";
    if (seq === serverSetup.seq) {
      serverSetupClearSecrets(); serverSetup.busy = false; serverSetup.phase = null; serverSetupRender();
    }
  }
}
async function serverSetupLoadJobs() {
  if (!serverSetupAllowed() || !$("addServerDialog").open) return;
  const seq = serverSetup.seq;
  try {
    const rows = await serverSetupApi("/api/v1/browser-ssh/agent/list", {}, 12000, seq);
    if (seq !== serverSetup.seq || !Array.isArray(rows)) return;
    serverSetup.jobs = rows.filter((row) => row && typeof row.request_id === "string" &&
      typeof row.name === "string" && typeof row.phase === "string");
    serverSetupRenderJobs();
    serverSetupRender();
  } catch { /* The SSH status check remains usable before a worker is installed. */ }
}
function serverSetupSelectRecovery() {
  const selected = $("serverSetupRecoverySelect").value;
  serverSetup.recovery = serverSetup.jobs.find((row) => row.request_id === selected && row.recoverable) || null;
  serverSetup.job = null;
  serverSetup.kind = null;
  $("serverSetupResult").hidden = true;
  $("serverSetupApplyConfirm").checked = false;
  serverSetupRenderJobs();
  serverSetupRender();
}
function serverSetupJobPreviewValid(reply) {
  return reply?.protocol === 1 && /^[0-9a-f-]{36}$/.test(reply.request_id || "") &&
    Number.isSafeInteger(reply.revision) && reply.revision >= 1 &&
    ["prepared", "transport_ready", "registered", "active"].includes(reply.phase) &&
    reply.writes === true && reply.activation_writes === false &&
    typeof reply.hub_fingerprint === "string" && serverSetupFingerprintPattern.test(reply.hub_fingerprint) &&
    typeof reply.platform?.ubuntu_version === "string" &&
    /^[0-9a-f]{40}$/.test(reply.source_commits?.["sovagrid-agent"] || "");
}
async function serverSetupReadCredentials(seq, reviewed) {
  const target = serverSetupTarget();
  if (target.host !== reviewed.host || target.port !== reviewed.port ||
      !$("serverSetupTrust").checked || serverSetup.changedPin)
    throw new Error("STALE_REQUEST");
  const username = $("serverSetupUsername").value.trim();
  const method = $("serverSetupAuthKey").checked ? "private_key" : "password";
  if (!serverSetupUsernamePattern.test(username)) throw new Error("INVALID_USERNAME");
  if (username !== "root") throw new Error("ROOT_REQUIRED");
  let password = "", private_key = "", passphrase = "";
  const file = method === "private_key" ? $("serverSetupPrivateKey").files?.[0] : null;
  try {
    if (method === "private_key") {
      if (!file || file.size < 1 || file.size > 65536) throw new Error("INVALID_KEY");
      try { private_key = await file.text(); } catch { throw new Error("FILE_READ_FAILED"); }
      passphrase = $("serverSetupPassphrase").value;
      if (!private_key || new TextEncoder().encode(private_key).length > 65536 || passphrase.length > 1024)
        throw new Error("INVALID_KEY");
    } else {
      password = $("serverSetupPassword").value;
      if (!password || password.length > 1024) throw new Error("PASSWORD_INVALID");
    }
    const currentMethod = $("serverSetupAuthKey").checked ? "private_key" : "password";
    if (seq !== serverSetup.seq || !$("addServerDialog").open || !serverSetupAllowed() ||
        !$("serverSetupTrust").checked || serverSetup.changedPin ||
        $("serverSetupUsername").value.trim() !== username ||
        currentMethod !== method ||
        (method === "private_key" && $("serverSetupPrivateKey").files?.[0] !== file))
      throw new Error("STALE_REQUEST");
    return { host: reviewed.host, port: reviewed.port, username, method,
      fingerprint: reviewed.fingerprint, password, private_key, passphrase };
  } finally {
    serverSetupClearSecrets();
    password = private_key = passphrase = "";
  }
}
function serverSetupInstallFields() {
  const name = $("serverSetupInstallName").value.trim();
  const hub_host = $("serverSetupHubHost").value.trim();
  const hub_port = Number($("serverSetupHubPort").value);
  const local_port = Number($("serverSetupLocalPort").value);
  if (!name || name.length > 80 || /[\r\n\x00-\x1f]/.test(name)) throw new Error("INVALID_NAME");
  if (!hub_host || hub_host.length > 45 || !/^[0-9a-fA-F:.]+$/.test(hub_host) ||
      !Number.isSafeInteger(hub_port) || hub_port < 1 || hub_port > 65535 ||
      !Number.isSafeInteger(local_port) || local_port < 1024 || local_port > 65535)
    throw new Error("INVALID_ENDPOINT");
  return { name, hub_host, hub_port, local_port };
}
async function serverSetupPrepare() {
  if (serverSetup.busy || !serverSetupAllowed() || !serverSetup.reviewed ||
      !$("serverSetupTrust").checked || serverSetup.changedPin || serverSetup.job) return;
  const recovery = serverSetup.recovery;
  if (!recovery && serverSetup.kind !== "missing") return;
  let fields;
  try { fields = recovery ? null : serverSetupInstallFields(); }
  catch (error) {
    serverSetupError(error.message === "INVALID_NAME" ? "Введите короткое название сервера." :
      "Укажите IP и SSH-порт Hub, доступные новому серверу, и локальный порт Agent.");
    return;
  }
  const reviewed = { ...serverSetup.reviewed };
  const seq = ++serverSetup.seq;
  const token = state.token;
  serverSetup.busy = true;
  serverSetup.phase = recovery ? "resume" : "prepare";
  serverSetupClearError();
  serverSetupRender();
  let ssh;
  try {
    ssh = await serverSetupReadCredentials(seq, reviewed);
    if (seq !== serverSetup.seq || state.token !== token) throw new Error("STALE_REQUEST");
    if (recovery) {
      const reply = await serverSetupApi("/api/v1/browser-ssh/agent/resume",
        { request_id: recovery.request_id, ...ssh }, 720000, seq);
      if (seq !== serverSetup.seq || state.token !== token) return;
      if (!serverSetupJobPreviewValid(reply) || reply.request_id !== recovery.request_id)
        throw new Error("INVALID_RESPONSE");
      serverSetup.job = reply;
    } else {
      const payload = { ...ssh, ...fields };
      const preview = await serverSetupApi("/api/v1/browser-ssh/target-install-preview",
        { ...payload }, 45000, seq);
      if (seq !== serverSetup.seq || state.token !== token) return;
      if (preview?.protocol !== 1 || preview.action !== "install_preview" ||
          preview.host !== reviewed.host || preview.port !== reviewed.port ||
          preview.host_key_fingerprint !== reviewed.fingerprint || preview.writes !== false)
        throw new Error("INVALID_RESPONSE");
      if (preview.target_kind !== "missing" || preview.hub_route !== "reachable" ||
          preview.preflight_passed !== true)
        throw new Error(preview.hub_route === "unreachable" ? "HUB_ROUTE_BLOCKED" : "TARGET_NOT_EMPTY");
      const reply = await serverSetupApi("/api/v1/browser-ssh/agent/prepare", payload, 720000, seq);
      if (seq !== serverSetup.seq || state.token !== token) return;
      if (!serverSetupJobPreviewValid(reply)) throw new Error("INVALID_RESPONSE");
      serverSetup.job = reply;
    }
    $("serverSetupApplyConfirm").checked = false;
    $("serverSetupResult").hidden = true;
    await serverSetupLoadJobs();
  } catch (error) {
    if (seq === serverSetup.seq) {
      if (error.message === "HOST_KEY_CHANGED") serverSetupInvalidate();
      const guidance = error.message === "INVALID_USERNAME" ? "Введите пользователя SSH без пробелов." :
        error.message === "ROOT_REQUIRED" ? "Для автоматической установки нужен SSH-вход пользователя root." :
        error.message === "INVALID_KEY" || error.message === "FILE_READ_FAILED" ? "Выберите читаемый приватный ключ до 64 КиБ и проверьте парольную фразу." :
        error.message === "PASSWORD_INVALID" ? "Введите пароль SSH длиной до 1024 символов." :
        error.message === "HUB_ROUTE_BLOCKED" ? "Новый сервер не может подключиться к SSH-порту Hub. Проверьте IP, порт и сеть." :
        error.message === "TARGET_NOT_EMPTY" ? "На сервере найдена существующая или конфликтующая установка. Выберите её в списке восстановления либо проверьте вручную." :
        serverSetupExplain(error);
      serverSetupError(error.requestId ? `${guidance} ID: ${error.requestId}` : guidance);
      void serverSetupLoadJobs();
    }
  } finally {
    if (ssh) for (const key of ["password", "private_key", "passphrase"]) ssh[key] = "";
    if (seq === serverSetup.seq) {
      serverSetupClearSecrets(); serverSetup.busy = false; serverSetup.phase = null; serverSetupRender();
    }
  }
}
async function serverSetupPollStatus(seq, requestId) {
  if (seq !== serverSetup.seq || !serverSetup.busy || !serverSetup.job) return;
  try {
    const row = await serverSetupApi("/api/v1/browser-ssh/agent/status",
      { request_id: requestId }, 12000, seq);
    if (seq !== serverSetup.seq || row?.request_id !== requestId) return;
    serverSetup.job = { ...serverSetup.job, ...row };
    serverSetupRenderJob();
  } catch { /* The original operation still owns the result; recovery remains available. */ }
}
async function serverSetupApply() {
  const job = serverSetup.job;
  if (serverSetup.busy || !job || job.phase === "active" || job.cleanup_required ||
      !$("serverSetupApplyConfirm").checked || !serverSetupAllowed()) return;
  const seq = ++serverSetup.seq;
  serverSetup.busy = true;
  serverSetup.phase = "apply";
  serverSetupClearError();
  serverSetupRender();
  serverSetup.pollTimer = setInterval(() => { void serverSetupPollStatus(seq, job.request_id); }, 5000);
  try {
    const reply = await serverSetupApi("/api/v1/browser-ssh/agent/apply",
      { request_id: job.request_id, expected_revision: job.revision }, 720000, seq);
    if (seq !== serverSetup.seq || reply?.request_id !== job.request_id) return;
    serverSetup.job = { ...serverSetup.job, ...reply };
    if (reply.phase === "active") void refresh();
  } catch (error) {
    if (seq === serverSetup.seq) {
      serverSetupError(serverSetupExplain(error));
      void serverSetupPollStatus(seq, job.request_id);
    }
  } finally {
    if (serverSetup.pollTimer) clearInterval(serverSetup.pollTimer);
    serverSetup.pollTimer = null;
    if (seq === serverSetup.seq) { serverSetup.busy = false; serverSetup.phase = null; serverSetupRender(); }
  }
}
async function serverSetupCleanup() {
  const job = serverSetup.job;
  if (serverSetup.busy || !job || job.phase === "active" || !serverSetupAllowed() ||
      !globalThis.confirm?.("Очистить временный пакет и незавершённую регистрацию этого Agent?")) return;
  const seq = ++serverSetup.seq;
  serverSetup.busy = true;
  serverSetup.phase = "cleanup";
  serverSetupClearError();
  serverSetupRender();
  try {
    const reply = await serverSetupApi("/api/v1/browser-ssh/agent/cleanup",
      { request_id: job.request_id, expected_revision: job.revision }, 720000, seq);
    if (seq !== serverSetup.seq || reply?.request_id !== job.request_id) return;
    if (reply.removed === true) {
      serverSetup.job = null;
      serverSetup.recovery = null;
      serverSetup.kind = null;
      $("serverSetupResultTitle").textContent = "Подготовка очищена";
      $("serverSetupResultText").textContent = "Временный пакет и запись незавершённой установки удалены. Другие серверы не изменены.";
      $("serverSetupResult").hidden = false;
      void serverSetupLoadJobs();
    } else serverSetup.job = { ...serverSetup.job, ...reply };
  } catch (error) {
    if (seq === serverSetup.seq) serverSetupError(serverSetupExplain(error));
  } finally {
    if (seq === serverSetup.seq) { serverSetup.busy = false; serverSetup.phase = null; serverSetupRender(); }
  }
}
async function serverSetupInterrupt() {
  if (!serverSetup.busy || !serverSetupAllowed()) return;
  const seq = serverSetup.seq;
  try {
    const reply = await serverSetupApi("/api/v1/browser-ssh/agent/interrupt",
      serverSetup.job ? { request_id: serverSetup.job.request_id } : {}, 12000, seq);
    if (seq === serverSetup.seq && reply?.cancel_requested === true)
      serverSetupError("Остановка запрошена. Проверьте состояние установки и при необходимости очистите её.");
  } catch (error) {
    if (seq === serverSetup.seq) serverSetupError(serverSetupExplain(error));
  }
}
function openAddServer() {
  clearError($("addServerError"));
  $("addServerDialog").showModal();
  serverSetupReset();
  void serverSetupLoadJobs();
  $("serverSetupHost").focus?.();
}

$("loginForm").addEventListener("submit", login);
$("changePasswordForm").addEventListener("submit", changeAdminPassword);
$("logoutButton").addEventListener("click", () => {
  if (globalThis.filesHasUnsavedChanges?.()) {
    setView("files");
    globalThis.filesWarnUnsavedChanges?.();
    return;
  }
  logout();
});
$("refreshButton").addEventListener("click", refresh);
$("addServerButton").addEventListener("click", openAddServer);
$("emptyAddButton").addEventListener("click", openAddServer);
document.querySelectorAll("[data-start-action]").forEach((button) => button.addEventListener("click", () => {
  if (button.dataset.startAction === "add") openAddServer();
  else setView(button.dataset.startAction);
}));
$("cancelAddButton").addEventListener("click", () => $("addServerDialog").close());
$("addServerDialog").addEventListener("close", serverSetupReset);
$("serverSetupSshTab").addEventListener("click", () => serverSetupMode("ssh"));
$("serverSetupAgentTab").addEventListener("click", () => serverSetupMode("agent"));
$("serverSetupHost").addEventListener("input", serverSetupInvalidate);
$("serverSetupPort").addEventListener("input", serverSetupInvalidate);
$("serverSetupInspect").addEventListener("click", () => { void serverSetupInspect(); });
$("serverSetupTrust").addEventListener("change", serverSetupRender);
$("serverSetupReplaceKey").addEventListener("click", () => {
  if (!serverSetup.reviewed || !serverSetup.changedPin || !globalThis.confirm?.(
    "Вы независимо сверили новый SSH-отпечаток этого сервера? Старый закреплённый ключ будет заменён только после успешной проверки.")) return;
  serverSetup.changedPin = false;
  $("serverSetupTrust").checked = false;
  serverSetupClearError();
  serverSetupRender();
});
$("serverSetupUsername").addEventListener("input", () => serverSetupCredentialsChanged());
$("serverSetupAuthPassword").addEventListener("change", () => serverSetupCredentialsChanged(true));
$("serverSetupAuthKey").addEventListener("change", () => serverSetupCredentialsChanged(true));
$("serverSetupPassword").addEventListener("input", () => serverSetupCredentialsChanged());
$("serverSetupPrivateKey").addEventListener("change", () => serverSetupCredentialsChanged());
$("serverSetupPassphrase").addEventListener("input", () => serverSetupCredentialsChanged());
$("serverSetupStatusForm").addEventListener("submit", (event) => { void serverSetupStatus(event); });
$("serverSetupRecoverySelect").addEventListener("change", serverSetupSelectRecovery);
$("serverSetupReloadJobs").addEventListener("click", () => { void serverSetupLoadJobs(); });
$("serverSetupPrepareButton").addEventListener("click", () => { void serverSetupPrepare(); });
$("serverSetupApplyConfirm").addEventListener("change", serverSetupRender);
$("serverSetupApplyButton").addEventListener("click", () => { void serverSetupApply(); });
$("serverSetupCleanupButton").addEventListener("click", () => { void serverSetupCleanup(); });
$("serverSetupInterruptButton").addEventListener("click", () => { void serverSetupInterrupt(); });
$("addServerForm").addEventListener("submit", addServer);
document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => setView(button.dataset.view)));
document.querySelectorAll("[data-command]").forEach((button) => button.addEventListener("click", () => { setView("commands"); $("commandInput").value = button.dataset.command; $("commandInput").focus(); }));
$("commandPermissionButton").addEventListener("click", toggleCommands);
$("commandForm").addEventListener("submit", prepareCommand);
$("runCommandButton").addEventListener("click", runCommand);
$("terminalStartButton").addEventListener("click", startTerminal);
$("terminalAddTabButton").addEventListener("click", addTerminalTab);
$("terminalReconnectButton").addEventListener("click", reconnectTerminal);
$("terminalCloseButton").addEventListener("click", closeTerminal);
document.querySelectorAll("[data-terminal-key]").forEach((button) =>
  button.addEventListener("click", () => sendTerminalKey(button.dataset.terminalKey)));
$("terminalInputForm").addEventListener("submit", sendTerminalLine);
$("terminalInputVisibility").addEventListener("click", toggleTerminalLineVisibility);
$("terminalInput").addEventListener("paste", rejectMultilineTerminalPaste);
globalThis.addEventListener?.("resize", fitTerminal);
globalThis.addEventListener?.("pagehide", () => {
  serverSetupReset();
  for (const terminal of terminalTabs.items) {
    if (terminal.sessionId) bestEffortDeleteTerminalSession(terminal.base, terminal.token, terminal.serverId, terminal.sessionId);
  }
  resetAllTerminals(false);
});
globalThis.addEventListener?.("pageshow", () => { if (state.token) renderTerminalControls(); });
globalThis.addEventListener?.("sovagridthemechange", () => {
  const palette = terminalPalette();
  for (const terminal of terminalTabs.items) if (terminal.term?.options) terminal.term.options.theme = palette;
});
$("cancelCommandButton").addEventListener("click", () => { if (!state.commandSubmitting) $("confirmCommandDialog").close(); });
$("confirmCommandDialog").addEventListener("cancel", (event) => { if (state.commandSubmitting) event.preventDefault(); });
$("confirmCommandDialog").addEventListener("close", () => { state.pendingCommand = ""; state.pendingServerId = null; state.pendingCommandKey = null; $("confirmCommandText").textContent = ""; });
$("vpnTargetServer").addEventListener("change", (event) => {
  const targetId = event.target.value;
  if (targetId === VPN_HUB_HOST ? !hubCanGlobalAdmin() :
      !state.servers.some((server) => String(server.id) === String(targetId))) return;
  state.vpnTargetId = targetId;
  state.vpnInventoryTargetId = null;
  state.vpn = { source_status: "loading" };
  renderVpn(state.vpn, vpnInventoryContext(targetId));
  if (state.token) void refresh();
});
$("vpnCreateForm").addEventListener("submit", prepareVpnCreate);
$("vpnInstanceForm").addEventListener("submit", prepareVpnInstance);
$("vpnClientForm").addEventListener("submit", prepareVpnClient);
$("vpnExportForm").addEventListener("submit", prepareVpnExport);
$("vpnProfileDownload").addEventListener("click", downloadVpnProfile);
$("vpnProfileShare").addEventListener("click", shareVpnProfile);
$("vpnRemoveName").addEventListener("input", () => { $("vpnActionConfirm").disabled = state.vpnPending?.payload.action === "remove" && $("vpnRemoveName").value !== state.vpnPending.payload.name; });
$("vpnActionConfirm").addEventListener("click", submitVpnAction);
$("vpnActionCancel").addEventListener("click", () => { if (!state.vpnSubmittingKey) $("vpnActionDialog").close(); });
$("vpnActionDialog").addEventListener("cancel", (event) => { if (state.vpnSubmittingKey) event.preventDefault(); });
$("vpnActionDialog").addEventListener("close", () => { if (!state.vpnSubmittingKey) { state.vpnPending = null; pendingSealedExport = null; } $("vpnRemoveName").value = ""; });
document.querySelectorAll("[data-chart]").forEach((button) => button.addEventListener("click", () => { state.chartField = button.dataset.chart; renderHistory(state.history); }));
$("copyTokenButton").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("agentToken").textContent); $("copyTokenButton").textContent = "Скопировано"; }
  catch { $("copyTokenButton").textContent = "Выделите токен вручную"; }
});
$("closeTokenButton").addEventListener("click", () => { $("tokenDialog").close(); $("agentToken").textContent = ""; $("copyTokenButton").textContent = "Копировать токен"; });
$("tokenDialog").addEventListener("close", () => { $("agentToken").textContent = ""; $("copyTokenButton").textContent = "Копировать токен"; });
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    if (serverSetup.busy) serverSetupInvalidate();
    else serverSetupClearSecrets();
  } else if (state.token) refresh();
});
const savedHub = localStorage.getItem("sovagrid.hub");
$("hubUrl").value = preferredHub(savedHub, location);
const sshBootstrapPending = trySSHBootstrap(sshBootstrapPort);
if ("serviceWorker" in navigator && ["http:", "https:"].includes(location.protocol)) {
  // The installer always launches this stable alias, including when the
  // visible panel path is changed by the administrator.
  const base = new URL("/sovagrid/monitoring/", location.origin);
  const scriptURL = new URL("sw.js", base).href;
  navigator.serviceWorker.register(scriptURL, { scope: base.pathname }).then(async (current) => {
    // A former release registered at '/'. Retire that broad worker only after
    // the worker at the stable panel alias has activated.
    if (base.pathname === "/" || typeof navigator.serviceWorker.getRegistrations !== "function") return;
    const active = () => current.active?.scriptURL === scriptURL && current.active.state === "activated";
    if (!active()) {
      const candidate = current.installing || current.waiting;
      if (!candidate || candidate.scriptURL !== scriptURL) return;
      const activated = await new Promise((resolve) => {
        let timer;
        const finish = (result) => {
          clearTimeout(timer);
          candidate.removeEventListener("statechange", changed);
          resolve(result);
        };
        const changed = () => {
          if (active() || candidate.state === "activated") finish(true);
          else if (candidate.state === "redundant") finish(false);
        };
        candidate.addEventListener("statechange", changed);
        timer = setTimeout(() => finish(false), 15000);
        changed();
      });
      if (!activated) return;
    }
    const legacyScript = new URL("/sw.js", location.origin).href;
    for (const registration of await navigator.serviceWorker.getRegistrations()) {
      if (registration.scope !== location.origin + "/" ||
          ![registration.active, registration.waiting, registration.installing]
            .some((worker) => worker?.scriptURL === legacyScript)) continue;
      await registration.unregister();
    }
  }).catch(() => {});
}

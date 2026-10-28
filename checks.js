/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

const checksClient = { generation: 0, seq: 0, serverId: null, data: null, pending: null,
  loading: false, busy: false, expanded: new Set(), histories: new Map(), historyEpoch: 0, historyRequests: new Map() };
const CHECK_STATES = { disabled: "Выключена", waiting: "Ожидаем Agent", up: "Доступен", down: "Недоступен", stale: "Данные устарели" };
const CHECK_ERRORS = { dns_error: "Не удалось определить адрес", connect_error: "Соединение не установлено",
  dns_mismatch: "DNS вернул другой адрес",
  timeout: "Время ожидания истекло", tls_error: "Сертификат не прошёл проверку",
  http_error: "Ответ HTTP вне 2xx", invalid_response: "Некорректный ответ сервиса",
  invalid_target: "Недопустимая цель", internal_error: "Проверка не завершилась", response_too_large: "Заголовки ответа слишком велики" };
const CHECK_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CHECK_CA_MAX_DER = 1536;

function checksContext() {
  const generation = checksClient.generation, token = state.token, base = state.base, sid = checksClient.serverId;
  return () => Boolean(token) && token === state.token && base === state.base &&
    generation === checksClient.generation && String(sid) === String(state.selectedId) &&
    String(sid) === String(checksClient.serverId);
}
function checksPath() { return `/api/v1/servers/${encodeURIComponent(checksClient.serverId)}/checks`; }
function checksDate(seconds) {
  return new Intl.DateTimeFormat("ru", { dateStyle: "medium", timeStyle: "short" }).format(new Date(seconds * 1000));
}
function checksDialogBusy(busy) {
  for (const id of ["checkName", "checkKind", "checkUrl", "checkHost", "checkPort", "checkInterval",
    "checkDnsHost", "checkRecordType", "checkExpectedIp", "checkTimeout", "checkEnabled", "checkTlsAlertEnabled",
    "checkTlsAlertDays", "checkCancel", "checkConfirm"]) $(id).disabled = busy;
  const kind = $("checkKind").value;
  $("checkUrl").disabled = busy || kind !== "http";
  $("checkHost").disabled = busy || kind !== "tcp";
  $("checkPort").disabled = busy || kind !== "tcp";
  $("checkDnsHost").disabled = busy || kind !== "dns";
  $("checkRecordType").disabled = busy || kind !== "dns";
  $("checkExpectedIp").disabled = busy || kind !== "dns";
  $("checkTlsAlertEnabled").disabled = busy || $("checkTlsAlertField").hidden;
  $("checkTlsAlertDays").disabled = busy || $("checkTlsAlertField").hidden || !$("checkTlsAlertEnabled").checked;
  checksCaControls(busy);
}
function checksHttps() {
  if ($("checkKind").value !== "http") return false;
  try { return new URL($("checkUrl").value.trim()).protocol === "https:"; }
  catch { return false; }
}
function checksCaControls(busy = checksClient.busy) {
  const pending = checksClient.pending;
  const enabled = Boolean(pending && pending.mode !== "delete" && checksHttps());
  $("checkCaField").hidden = !enabled;
  $("checkCaFile").disabled = busy || !enabled || Boolean(pending?.caLoading);
  $("checkCaClear").disabled = busy || !enabled || Boolean(pending?.caLoading) || (!pending.caCertDerB64 && !pending.caError);
  $("checkCaClear").textContent = pending?.caError ? "Сбросить неверный файл" : "Удалить свой CA";
  $("checkConfirm").disabled = busy || Boolean(pending?.caLoading || enabled && pending?.caError);
  $("checkCaStatus").textContent = pending?.caLoading ? "Читаю сертификат…" :
    pending?.caCertDerB64 ? pending.caChanged ? "Новый CA выбран; сохраните проверку." : "Свой CA уже настроен." :
      pending?.caChanged ? "Свой CA будет удалён после сохранения." : "Используется системное доверие.";
}
function checksCaDerB64(bytes) {
  if (bytes.length > 4096 || !bytes.length) throw new Error("Выберите один CA-сертификат PEM или DER размером до 1,5 КБ в DER.");
  let der = bytes;
  const content = String.fromCharCode(...bytes);
  if (/^\s*-----BEGIN/.test(content)) {
    const match = /^\s*-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----\s*$/.exec(content);
    if (!match) throw new Error("Файл должен содержать один CA-сертификат, без ключей и других данных.");
    const encoded = match[1].replace(/\s/g, "");
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded))
      throw new Error("Неверный формат PEM-сертификата.");
    try {
      const decoded = atob(encoded);
      if (btoa(decoded) !== encoded) throw new Error();
      der = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
    } catch { throw new Error("Неверный формат PEM-сертификата."); }
  }
  if (der.length < 1 || der.length > CHECK_CA_MAX_DER)
    throw new Error("CA-сертификат в DER должен занимать не более 1,5 КБ.");
  return btoa(String.fromCharCode(...der));
}
async function checksCaSelected() {
  const pending = checksClient.pending, file = $("checkCaFile").files?.[0];
  if (!pending || pending.mode === "delete" || !checksHttps() || checksClient.busy || !file) return;
  const current = checksContext(), sequence = (pending.caReadSequence || 0) + 1;
  pending.caReadSequence = sequence; pending.caLoading = true; checksCaControls();
  try {
    if (file.size > 4096) throw new Error("Файл слишком большой: выберите один CA-сертификат PEM или DER.");
    const encoded = checksCaDerB64(new Uint8Array(await file.arrayBuffer()));
    if (!current() || checksClient.pending !== pending || pending.caReadSequence !== sequence || !checksHttps()) return;
    pending.caCertDerB64 = encoded; pending.caChanged = true; pending.caError = false;
    clearError($("checkDialogError"));
  } catch (error) {
    if (current() && checksClient.pending === pending && pending.caReadSequence === sequence) {
      pending.caError = true;
      showError($("checkDialogError"), error.message || "Не удалось прочитать сертификат.");
    }
  } finally {
    if (current() && checksClient.pending === pending && pending.caReadSequence === sequence) {
      pending.caLoading = false; $("checkCaFile").value = ""; checksCaControls();
    }
  }
}
function checksCaClear() {
  const pending = checksClient.pending;
  if (!pending || pending.mode === "delete" || !checksHttps() || checksClient.busy || pending.caLoading) return;
  if (pending.caError) pending.caError = false;
  else {
    pending.caCertDerB64 = null;
    pending.caChanged = Boolean(pending.config.checks.find((row) => row.id === pending.id)?.ca_cert_der_b64);
  }
  $("checkCaFile").value = ""; clearError($("checkDialogError")); checksCaControls();
}
function checksReset() {
  checksClient.generation++; checksClient.seq++;
  Object.assign(checksClient, { serverId: null, data: null, pending: null, loading: false, busy: false });
  checksClient.historyEpoch++; checksClient.historyRequests.clear();
  checksClient.expanded.clear(); checksClient.histories.clear();
  if ($("checkDialog").open) $("checkDialog").close();
  for (const id of ["checkName", "checkUrl", "checkHost", "checkPort", "checkDnsHost", "checkExpectedIp"]) $(id).value = "";
  $("checkCaFile").value = "";
  $("checkTlsAlertEnabled").checked = false; $("checkTlsAlertDays").value = "14"; checksTlsControls();
  checksDialogBusy(false); clearError($("checksError")); clearError($("checkDialogError"));
  $("checksMessage").hidden = true; $("checksMessage").textContent = "";
  checksRender();
}
globalThis.checksReset = checksReset;
function checksSelectedServer(sid) {
  if (String(sid) === String(checksClient.serverId)) return;
  checksReset(); checksClient.serverId = sid;
}
globalThis.checksSelectedServer = checksSelectedServer;

function checksResult(value) {
  if (value === null) return null;
  if (!value || !["up", "down"].includes(value.status) || !Number.isSafeInteger(value.observed_at) || value.observed_at < 0 ||
      !(value.latency_ms === null || Number.isInteger(value.latency_ms) && value.latency_ms >= 0 && value.latency_ms <= 10000) ||
      !(value.http_status === null || Number.isInteger(value.http_status) && value.http_status >= 100 && value.http_status <= 599) ||
      !(value.tls_expires_at === null || Number.isSafeInteger(value.tls_expires_at) && value.tls_expires_at > 0) ||
      !(value.error_code === null || typeof value.error_code === "string" && /^[a-z_]{1,40}$/.test(value.error_code)))
    throw new Error("Hub вернул неверный результат проверки.");
  return value;
}
function checksSummary(payload, sid) {
  if (!payload || String(payload.server_id) !== String(sid) || !Number.isSafeInteger(payload.revision) || payload.revision < 0 ||
      !(payload.worker_seen_at === null || Number.isSafeInteger(payload.worker_seen_at)) || !Array.isArray(payload.checks) || payload.checks.length > 16)
    throw new Error("Hub вернул неверный список проверок.");
  const ids = new Set();
  for (const row of payload.checks) {
    if (!row || !CHECK_UUID.test(row.id) || ids.has(row.id) || typeof row.name !== "string" || !row.name || row.name.length > 160 ||
        !["http", "tcp", "dns"].includes(row.kind) || typeof row.enabled !== "boolean" || !Object.hasOwn(CHECK_STATES, row.state) ||
        !Number.isInteger(row.interval_seconds) || row.interval_seconds < 60 || row.interval_seconds > 3600 ||
        !Number.isInteger(row.timeout_seconds) || row.timeout_seconds < 1 || row.timeout_seconds > 10 ||
        !(row.tls_alert_days === undefined || row.tls_alert_days === null ||
          Number.isInteger(row.tls_alert_days) && row.tls_alert_days >= 1 && row.tls_alert_days <= 90))
      throw new Error("Hub вернул неверную проверку.");
    ids.add(row.id); checksResult(row.latest);
  }
  return payload;
}
function checksResultText(result) {
  if (!result) return "Запусков ещё не было.";
  return [checksDate(result.observed_at), result.http_status === null ? null : `HTTP ${result.http_status}`,
    result.latency_ms === null ? null : `${Math.round(result.latency_ms)} мс`,
    result.error_code === null ? null : CHECK_ERRORS[result.error_code] || "Проверка не завершилась"].filter(Boolean).join(" · ");
}
function checksRender() {
  const client = checksClient, data = client.data;
  $("checksCount").textContent = data ? String(data.checks.length) : "—";
  $("checksAdd").disabled = !hubCanAdmin() || !data || data.checks.length >= 16 || client.loading || client.busy;
  $("checksReload").disabled = client.busy || client.loading || state.selectedId === null;
  $("checksWorker").textContent = data ? data.worker_seen_at === null
    ? "Agent ещё не запрашивал проверки. Для этой функции требуется обновление Agent."
    : `Последний запрос Agent: ${checksDate(data.worker_seen_at)}. Интервал обновления панели — 15 секунд.` : "";
  const list = $("checksList"); list.replaceChildren();
  if (!data?.checks.length) {
    const empty = document.createElement("p"); empty.className = "field-help";
    empty.textContent = data ? "Проверок пока нет. Администратор может добавить сайт, TCP-порт или DNS-запись." : client.loading ? "Получаем проверки…" : "Результаты пока недоступны.";
    list.append(empty); return;
  }
  for (const row of data.checks) {
    const article = document.createElement("article"); article.className = "check-row";
    const heading = document.createElement("h3"); heading.textContent = row.name;
    const summary = document.createElement("div"); summary.className = "check-summary";
    const badge = document.createElement("span"); badge.className = `status-badge ${row.state === "up" ? "" : row.state === "down" ? "offline" : "waiting"}`;
    badge.textContent = CHECK_STATES[row.state];
    const kind = document.createElement("span"); kind.className = "field-help";
    kind.textContent = `${row.kind === "tcp" ? "TCP" : row.kind === "dns" ? "DNS" : "HTTP / HTTPS"} · каждые ${row.interval_seconds} с`;
    summary.append(badge, kind);
    const latest = document.createElement("p"); latest.textContent = checksResultText(row.latest);
    article.append(heading, summary, latest);
    if (row.latest?.tls_expires_at) {
      const tls = document.createElement("p");
      const remaining = row.latest.tls_expires_at - Date.now() / 1000;
      // The local 14-day visual cue is independent of the optional incident
      // threshold, which controls durable alerts and Telegram notifications.
      tls.className = remaining <= 14 * 86400 ? "check-tls-warning" : "";
      const alert = row.tls_alert_days == null ? "Оповещение выключено." : `Оповещение за ${row.tls_alert_days} дн.`;
      tls.textContent = `Сертификат действителен до ${checksDate(row.latest.tls_expires_at)}. ${alert}${tls.className ? remaining <= 0 ? " Срок сертификата истёк. Требуется обновление сертификата." : " Требуется обновление сертификата." : ""}`;
      article.append(tls);
    } else if (row.kind === "http" && row.tls_alert_days != null) {
      const tls = document.createElement("p"); tls.textContent = `Оповещение о сроке сертификата: за ${row.tls_alert_days} дн. Данные сертификата появятся после успешной HTTPS-проверки.`;
      article.append(tls);
    }
    const actions = document.createElement("div"); actions.className = "checks-actions";
    if (hubCanAdmin()) for (const [mode, label] of [["run", "Проверить сейчас"], ["edit", "Изменить"], ["delete", "Удалить"]]) {
      const button = document.createElement("button"); button.type = "button"; button.className = "secondary-button";
      button.textContent = label; button.setAttribute("aria-label", `${label}: ${row.name}`);
      button.disabled = client.busy || client.loading || mode === "run" && !row.enabled;
      button.addEventListener("click", () => mode === "run" ? checksRun(row.id) : checksOpen(mode, row.id)); actions.append(button);
    }
    article.append(actions);
    const details = document.createElement("details"), title = document.createElement("summary"), history = document.createElement("ol");
    title.textContent = "История запусков"; history.className = "check-history";
    details.append(title, history);
    if (client.histories.has(row.id)) checksHistoryRows(history, client.histories.get(row.id));
    details.addEventListener("toggle", () => {
      if (details.open) { client.expanded.add(row.id); void checksHistory(row.id, history); }
      else client.expanded.delete(row.id);
    });
    details.open = client.expanded.has(row.id);
    article.append(details); list.append(article);
  }
}
async function checksRefresh() {
  if (!state.token || state.selectedId === null || checksClient.busy) return;
  checksSelectedServer(state.selectedId);
  const current = checksContext(), sid = checksClient.serverId, seq = ++checksClient.seq;
  checksClient.loading = true; checksRender();
  try {
    const payload = await request(checksPath());
    if (!current() || seq !== checksClient.seq) return;
    checksSummary(payload, sid);
    if (checksClient.data && payload.revision !== checksClient.data.revision) {
      checksClient.historyEpoch++; checksClient.historyRequests.clear();
      checksClient.histories.clear(); checksClient.expanded.clear();
    }
    checksClient.data = payload;
    const ids = new Set(payload.checks.map((row) => row.id));
    for (const id of checksClient.histories.keys()) if (!ids.has(id)) checksClient.histories.delete(id);
    for (const id of checksClient.expanded) if (!ids.has(id)) checksClient.expanded.delete(id);
    clearError($("checksError"));
  } catch (error) {
    if (current() && seq === checksClient.seq) {
      checksClient.data = null;
      checksClient.historyEpoch++; checksClient.historyRequests.clear();
      checksClient.histories.clear();
      showError($("checksError"), error.status === 404 ? "Обновите Hub, чтобы настроить сетевые проверки." : error.message || "Не удалось загрузить проверки.");
    }
  } finally { if (current() && seq === checksClient.seq) { checksClient.loading = false; checksRender(); } }
}
globalThis.checksRefresh = checksRefresh;
function checksHistoryRows(list, rows) {
  list.replaceChildren();
  for (const row of rows) {
    const item = document.createElement("li");
    item.textContent = `${row.status === "up" ? "Доступен" : "Недоступен"} · ${checksResultText(row)}`; list.append(item);
  }
  if (!rows.length) { const item = document.createElement("li"); item.textContent = "История пока пуста."; list.append(item); }
}
async function checksHistory(id, list) {
  const bound = checksContext(), epoch = checksClient.historyEpoch;
  const seq = (checksClient.historyRequests.get(id) || 0) + 1;
  checksClient.historyRequests.set(id, seq);
  const current = () => bound() && epoch === checksClient.historyEpoch && checksClient.historyRequests.get(id) === seq;
  list.replaceChildren();
  try {
    const payload = await request(`${checksPath()}/${encodeURIComponent(id)}/history?limit=60`);
    if (!current()) return;
    if (String(payload.server_id) !== String(checksClient.serverId) || payload.check_id !== id ||
        !Array.isArray(payload.results) || payload.results.length > 60) throw new Error("Неверная история проверок.");
    for (const row of payload.results) {
      if (row === null) throw new Error("Неверная запись истории проверок.");
      checksResult(row);
    }
    checksClient.histories.set(id, payload.results);
    checksHistoryRows(list, payload.results);
  } catch (error) { if (current()) { const item = document.createElement("li"); item.textContent = error.message || "История недоступна."; list.append(item); } }
}
function checksKindChanged() {
  const kind = $("checkKind").value;
  $("checkUrlField").hidden = kind !== "http"; $("checkTcpFields").hidden = kind !== "tcp";
  $("checkDnsFields").hidden = kind !== "dns";
  $("checkUrl").required = kind === "http"; $("checkHost").required = kind === "tcp";
  $("checkPort").required = kind === "tcp"; $("checkDnsHost").required = kind === "dns";
  checksDnsTypeChanged();
  checksTlsControls();
}
function checksTlsControls() {
  const https = checksHttps();
  $("checkTlsAlertField").hidden = !https;
  $("checkTlsAlertDaysField").hidden = !https || !$("checkTlsAlertEnabled").checked;
  $("checkTlsAlertDays").required = https && $("checkTlsAlertEnabled").checked;
  checksDialogBusy(checksClient.busy);
}
function checksDnsTypeChanged() {
  const ipv6 = $("checkRecordType").value === "AAAA";
  $("checkExpectedIp").placeholder = ipv6 ? "2001:db8::1" : "203.0.113.10";
  $("checkExpectedIp").inputMode = ipv6 ? "text" : "decimal";
}
async function checksOpen(mode, id = null) {
  if (!state.token || !hubCanAdmin() || checksClient.busy || !checksClient.data || !["create", "edit", "delete"].includes(mode)) return;
  const current = checksContext(); checksClient.busy = true; checksClient.seq++; checksRender();
  try {
    const config = await request(`${checksPath()}/config`);
    if (!current() || !hubCanAdmin()) return;
    if (String(config.server_id) !== String(checksClient.serverId) || !Number.isSafeInteger(config.revision) || config.revision < 0 ||
        !Array.isArray(config.checks) || config.checks.length > 16 || config.checks.some((row) => !row || !CHECK_UUID.test(row.id))) throw new Error("Неверные настройки проверок.");
    const row = config.checks.find((item) => item.id === id);
    if (mode !== "create" && !row) throw new Error("Проверка уже удалена. Обновите список.");
    if (mode === "create" && config.checks.length >= 16) throw new Error("Можно добавить до 16 проверок на сервер.");
    if (row?.ca_cert_der_b64 != null && (typeof row.ca_cert_der_b64 !== "string" || row.ca_cert_der_b64.length > 2048))
      throw new Error("Неверные настройки сертификата проверки.");
    checksClient.pending = { mode, id, config, caCertDerB64: row?.ca_cert_der_b64 || null,
      caChanged: false, caLoading: false, caError: false };
    for (const field of ["checkName", "checkInterval", "checkTimeout"]) $(field).required = mode !== "delete";
    $("checkDialogHeading").textContent = mode === "delete" ? "Удалить проверку?" : mode === "edit" ? "Изменить проверку" : "Новая проверка";
    $("checkDialogTarget").textContent = mode === "delete" ? `${row.name}. История этой проверки будет удалена.` : "Цель проверяется с выбранного Agent, включая его локальную сеть.";
    $("checkFields").hidden = mode === "delete"; $("checkDialogNotice").hidden = mode === "delete";
    $("checkName").value = row?.name || ""; $("checkKind").value = row?.kind || "http";
    $("checkUrl").value = row?.url || ""; $("checkHost").value = row?.kind === "tcp" ? row.host : "";
    $("checkPort").value = row?.port ?? ""; $("checkDnsHost").value = row?.kind === "dns" ? row.host : "";
    $("checkRecordType").value = row?.record_type || "A"; $("checkExpectedIp").value = row?.expected_ip || "";
    $("checkTlsAlertEnabled").checked = Number.isInteger(row?.tls_alert_days) && row.tls_alert_days >= 1 && row.tls_alert_days <= 90;
    $("checkTlsAlertDays").value = $("checkTlsAlertEnabled").checked ? String(row.tls_alert_days) : "14";
    $("checkCaFile").value = "";
    $("checkInterval").value = row?.interval_seconds ?? 60; $("checkTimeout").value = row?.timeout_seconds ?? 5;
    $("checkEnabled").checked = row?.enabled ?? true; checksKindChanged();
    for (const field of ["checkName", "checkInterval", "checkTimeout", "checkUrl", "checkHost", "checkPort", "checkDnsHost"]) if (mode === "delete") $(field).required = false;
    $("checkConfirm").textContent = mode === "delete" ? "Удалить" : "Сохранить";
    clearError($("checkDialogError")); checksDialogBusy(false); $("checkDialog").showModal();
    (mode === "delete" ? $("checkConfirm") : $("checkName")).focus?.();
  } catch (error) { if (current()) showError($("checksError"), error.message || "Не удалось загрузить настройки."); }
  finally { if (current()) { checksClient.busy = false; checksClient.loading = false; checksRender(); } }
}
function checksDefinition(id) {
  const name = $("checkName").value.trim(), kind = $("checkKind").value;
  const interval = Number($("checkInterval").value), timeout = Number($("checkTimeout").value);
  if (!name || [...name].length > 80 || /[\u0000-\u001f\u007f-\u009f]/.test(name)) throw new Error("Введите название длиной до 80 символов.");
  if (!Number.isInteger(interval) || interval < 60 || interval > 3600 || !Number.isInteger(timeout) || timeout < 1 || timeout > 10) throw new Error("Интервал — 60–3600 секунд, тайм-аут — 1–10 секунд.");
  const definition = { id, name, kind, enabled: $("checkEnabled").checked, interval_seconds: interval, timeout_seconds: timeout };
  if (kind === "http") {
    const value = $("checkUrl").value.trim(); let url;
    try { url = new URL(value); } catch { throw new Error("Укажите полный адрес HTTP или HTTPS."); }
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || value.includes("?") || value.includes("#") || /[\s\\\u0000-\u001f\u007f]/.test(value) || new TextEncoder().encode(value).length > 1024)
      throw new Error("Нужен адрес HTTP/HTTPS без логина, пароля, пробелов и параметров.");
    definition.url = value;
    if (url.protocol === "https:") {
      if (checksClient.pending?.caLoading) throw new Error("Дождитесь чтения CA-сертификата.");
      if (checksClient.pending?.caError) throw new Error("Выберите корректный CA-сертификат или отмените изменение.");
      if (checksClient.pending?.caCertDerB64) definition.ca_cert_der_b64 = checksClient.pending.caCertDerB64;
      else if (checksClient.pending?.caChanged) definition.ca_cert_der_b64 = null;
      if ($("checkTlsAlertEnabled").checked) {
        const raw = $("checkTlsAlertDays").value, days = Number(raw);
        if (!/^[0-9]+$/.test(raw) || !Number.isInteger(days) || days < 1 || days > 90)
          throw new Error("Укажите срок предупреждения от 1 до 90 дней.");
        definition.tls_alert_days = days;
      } else if (checksClient.pending?.config.checks.some((row) => row.id === id && Object.hasOwn(row, "tls_alert_days"))) {
        // An explicit null turns off a previously configured alert. Omitting
        // the field would preserve it for older clients editing the same URL.
        definition.tls_alert_days = null;
      }
    }
  } else if (kind === "tcp") {
    const host = $("checkHost").value.trim(), port = Number($("checkPort").value);
    if (!host || host.length > 253 || /[\s/@?#%\\]/.test(host) || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Укажите хост без схемы и TCP-порт от 1 до 65535.");
    definition.host = host; definition.port = port;
  } else if (kind === "dns") {
    const host = $("checkDnsHost").value.trim(), recordType = $("checkRecordType").value;
    const expected = $("checkExpectedIp").value.trim();
    const labels = host.replace(/\.$/, "").split(".");
    if (!host || host.length > 253 || !/^[\x21-\x7e]+$/.test(host) ||
        /^[0-9.]+$/.test(host) || labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)))
      throw new Error("Укажите доменное имя без схемы, порта и пробелов.");
    if (!["A", "AAAA"].includes(recordType)) throw new Error("Выберите тип DNS-записи A или AAAA.");
    if (expected) {
      if (recordType === "A") {
        const parts = expected.split(".");
        if (parts.length !== 4 || parts.some((part) => !/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255))
          throw new Error("Для записи A ожидаемый адрес должен быть IPv4.");
      } else {
        try { if (!expected.includes(":") || !new URL(`http://[${expected}]/`).hostname.startsWith("[")) throw new Error(); }
        catch { throw new Error("Для записи AAAA ожидаемый адрес должен быть IPv6."); }
      }
    }
    definition.host = host; definition.record_type = recordType; definition.expected_ip = expected || null;
  } else throw new Error("Выберите HTTP/HTTPS, TCP или DNS.");
  return definition;
}
function checksClose() {
  if (checksClient.busy) return;
  checksClient.pending = null; if ($("checkDialog").open) $("checkDialog").close();
  $("checkUrl").value = ""; $("checkHost").value = ""; $("checkDnsHost").value = ""; $("checkExpectedIp").value = "";
  $("checkCaFile").value = "";
  $("checkTlsAlertEnabled").checked = false; $("checkTlsAlertDays").value = "14"; checksTlsControls();
}
async function checksSubmit(event) {
  event.preventDefault();
  const pending = checksClient.pending;
  if (!pending || checksClient.busy || !state.token || !hubCanAdmin()) return;
  let rows;
  try {
    rows = pending.config.checks.filter((row) => row.id !== pending.id);
    if (pending.mode !== "delete") rows.push(checksDefinition(pending.id || crypto.randomUUID()));
  } catch (error) { showError($("checkDialogError"), error.message); return; }
  const current = checksContext(); checksClient.busy = true; checksClient.seq++;
  checksClient.historyEpoch++; checksClient.historyRequests.clear();
  checksClient.histories.clear(); checksClient.expanded.clear();
  checksDialogBusy(true); checksRender();
  try {
    await request(`${checksPath()}/config`, { method: "POST", body: JSON.stringify({ revision: pending.config.revision, checks: rows }) });
    if (!current()) return;
    checksClient.histories.clear(); checksClient.expanded.clear();
    checksClient.pending = null; $("checkDialog").close(); $("checkUrl").value = ""; $("checkHost").value = "";
    $("checkDnsHost").value = ""; $("checkExpectedIp").value = "";
    $("checkCaFile").value = "";
    $("checkTlsAlertEnabled").checked = false; $("checkTlsAlertDays").value = "14"; checksTlsControls();
    $("checksMessage").textContent = pending.mode === "delete" ? "Проверка удалена." : "Проверка сохранена. Ожидаем следующий запуск Agent.";
    $("checksMessage").hidden = false; clearError($("checksError"));
  } catch (error) {
    if (current()) showError($("checkDialogError"), error.status === 409
      ? "Настройки уже изменились. Закройте окно и откройте проверку заново; ваши изменения не применены."
      : "Не удалось подтвердить сохранение. Закройте окно и обновите список перед повторной попыткой.");
    if (current()) checksClient.pending = null; // Never blindly replay an uncertain mutation.
  } finally { if (current()) { checksClient.busy = false; checksDialogBusy(false); $("checkConfirm").disabled = !checksClient.pending; await checksRefresh(); } }
}
async function checksRun(id) {
  if (!state.token || !hubCanAdmin() || !checksClient.data || checksClient.busy) return;
  const row = checksClient.data.checks.find((item) => item.id === id);
  if (!row?.enabled) return;
  const current = checksContext(), revision = checksClient.data.revision;
  checksClient.busy = true; checksClient.seq++; checksRender();
  try {
    await request(`${checksPath()}/${encodeURIComponent(id)}/run`, { method: "POST", body: JSON.stringify({ revision }) });
    if (current()) { $("checksMessage").hidden = false; $("checksMessage").textContent = "Запуск запрошен. Agent выполнит его, когда освободится worker."; clearError($("checksError")); }
  } catch (error) {
    if (current()) showError($("checksError"), error.status === 409 ? "Настройки изменились или запуск уже запрошен. Обновите результаты." : error.status === 429 ? "Этот запуск недавно запрошен. Повторите через 10 секунд." : error.message || "Запуск не подтверждён. Обновите результаты.");
  } finally { if (current()) { checksClient.busy = false; await checksRefresh(); } }
}
$("checksAdd").addEventListener("click", () => checksOpen("create"));
$("checksReload").addEventListener("click", checksRefresh);
$("checkKind").addEventListener("change", checksKindChanged);
$("checkUrl").addEventListener("input", checksTlsControls);
$("checkTlsAlertEnabled").addEventListener("change", checksTlsControls);
$("checkCaFile").addEventListener("change", checksCaSelected);
$("checkCaClear").addEventListener("click", checksCaClear);
$("checkRecordType").addEventListener("change", checksDnsTypeChanged);
$("checkCancel").addEventListener("click", checksClose);
$("checkForm").addEventListener("submit", checksSubmit);
$("checkDialog").addEventListener("cancel", (event) => { if (checksClient.busy) event.preventDefault(); else checksClient.pending = null; });
$("checkDialog").addEventListener("close", () => { if (!checksClient.busy) checksClient.pending = null; $("checkCaFile").value = ""; });

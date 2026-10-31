/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// All state is scoped to this tab. The four apply hashes come only from a
// fresh root preflight; they are never persisted or reconstructed from text.
const externalAgentUpdateClient = { generation: 0, reviewSeq: 0, loading: false,
  busy: false, status: null, plan: null, operation: null, operationExpectedHub: null,
  operationLoading: false, pollTimer: null, pollStarted: 0, recent: [], recentLoaded: false,
  recentLoading: false, recentError: "", error: "", notice: "",
  errorFromAction: false, lastRefresh: 0 };
const EXTERNAL_AGENT_SHA = /^[0-9a-f]{64}$/;
const EXTERNAL_AGENT_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const EXTERNAL_AGENT_PATH = /^[A-Za-z0-9_./-]{1,256}$/;
const EXTERNAL_AGENT_OPERATIONS = new Set(["create", "replace", "remove"]);
const EXTERNAL_AGENT_GATES = new Set(["ORIGINAL_HUB_AGENT_UPDATE_LEASE",
  "AGENT_IDLE_ACK", "TRIAL_FD_WATCHDOG"]);
const EXTERNAL_AGENT_PHASES = new Set(["accepted", "running", "complete", "failed", "uncertain"]);
const EXTERNAL_AGENT_PHASE_LABELS = { accepted: "Принята", running: "Выполняется",
  complete: "Завершена", failed: "Ошибка", uncertain: "Требует проверки" };

function externalAgentUpdateOperationRecord(value, requestId = null) {
  const keys = ["format", "request_id", "phase", "created_at", "updated_at", "error"];
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key)) ||
      value.format !== 1 || !EXTERNAL_AGENT_UUID.test(value.request_id) ||
      (requestId !== null && value.request_id !== requestId) ||
      !EXTERNAL_AGENT_PHASES.has(value.phase) ||
      !Number.isSafeInteger(value.created_at) || value.created_at < 1 ||
      value.created_at > 253402300799 || !Number.isSafeInteger(value.updated_at) ||
      value.updated_at < value.created_at || value.updated_at > 253402300799 ||
      (value.phase === "accepted" || value.phase === "running" || value.phase === "complete" ?
        value.error !== null : typeof value.error !== "string" ||
          !/^[A-Z][A-Z0-9_]{1,63}$/.test(value.error)))
    throw new Error("Hub вернул неверное состояние операции Agent.");
  return value;
}

function externalAgentUpdateRequestId() {
  if (!globalThis.crypto?.randomUUID) throw new Error("Для подтверждения нужен защищённый адрес панели.");
  const value = globalThis.crypto.randomUUID();
  if (!EXTERNAL_AGENT_UUID.test(value)) throw new Error("Не удалось создать номер запроса.");
  return value;
}

function externalAgentUpdateCurrent(generation, token, base) {
  return externalAgentUpdateClient.generation === generation &&
    state.token === token && state.base === base && Boolean(token) && hubCanGlobalAdmin();
}

function externalAgentUpdateStatus(value) {
  const keys = ["protocol", "hub_only", "current_hub_manifest_sha256",
    "external_agent_manifest_sha256", "idle_endpoint_present", "live_idle_ack_verified"];
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key)) ||
      value.protocol !== 1 || typeof value.hub_only !== "boolean" ||
      !EXTERNAL_AGENT_SHA.test(value.current_hub_manifest_sha256) ||
      typeof value.idle_endpoint_present !== "boolean" ||
      value.live_idle_ack_verified !== false ||
      (value.hub_only ? !EXTERNAL_AGENT_SHA.test(value.external_agent_manifest_sha256) :
        value.external_agent_manifest_sha256 !== null || value.idle_endpoint_present))
    throw new Error("Hub вернул неверное состояние внешнего Agent.");
  return value;
}

function externalAgentUpdateChanges(value) {
  return Array.isArray(value) && value.length > 0 && value.length <= 256 &&
    value.every((entry) => entry && typeof entry === "object" && !Array.isArray(entry) &&
      Object.keys(entry).length === 2 && typeof entry.path === "string" &&
      EXTERNAL_AGENT_PATH.test(entry.path) && EXTERNAL_AGENT_OPERATIONS.has(entry.operation));
}

function externalAgentUpdatePreview(value, status) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      value.protocol !== 1 || value.current_hub_manifest_sha256 !== status.current_hub_manifest_sha256 ||
      value.candidate_manifest_sha256 !== status.current_hub_manifest_sha256 ||
      value.external_agent_manifest_sha256 !== status.external_agent_manifest_sha256 ||
      value.external_agent_preserved !== true || value.tunnel_active !== true ||
      value.original_hub_compatibility !== "verified_same_bundle" ||
      typeof value.apply_supported !== "boolean" || value.explicit_review_required !== true ||
      !externalAgentUpdateChanges(value.source_paths_to_change) ||
      !Array.isArray(value.apply_blockers) || value.apply_blockers.length > 8 ||
      value.apply_blockers.some((code) => typeof code !== "string" || !/^[A-Z][A-Z0-9_]{1,63}$/.test(code)))
    throw new Error("Hub вернул неверный предварительный план Agent.");
  return value;
}

function externalAgentUpdatePreflight(value, status, archive) {
  externalAgentUpdatePreview(value, status);
  const paths = value.metadata_paths_to_change;
  const gates = value.live_gates_pending;
  if (value.archive_sha256 !== archive || !EXTERNAL_AGENT_SHA.test(value.review_sha256) ||
      !EXTERNAL_AGENT_SHA.test(value.baseline_sha256) ||
      !EXTERNAL_AGENT_SHA.test(value.enrollment_sha256) ||
      !Number.isSafeInteger(value.candidate_agent_file_count) ||
      value.candidate_agent_file_count < 1 || value.candidate_agent_file_count > 256 ||
      value.apply_supported !== true || value.apply_blockers.length !== 0 ||
      !Array.isArray(paths) || paths.length !== 3 || paths.some((path) =>
        typeof path !== "string" || !EXTERNAL_AGENT_PATH.test(path)) ||
      !Array.isArray(gates) || gates.length !== EXTERNAL_AGENT_GATES.size ||
      gates.some((code) => !EXTERNAL_AGENT_GATES.has(code)) || new Set(gates).size !== gates.length)
    throw new Error("Hub вернул неверный окончательный план Agent.");
  return value;
}

function externalAgentUpdateExplain(error, action = false) {
  if (error?.message === "Пакет не поддерживает безопасное обновление внешнего Agent.")
    return error.message;
  if (error?.status === 400 && error?.message === "INVALID_REQUEST")
    return "Проверьте SHA-256 архива и повторите подготовку плана.";
  if (error?.status === 404) return "Обновите Hub, чтобы управлять внешним Agent из панели.";
  if (error?.status === 401 || error?.status === 403)
    return "Нужен полный доступ администратора этого Hub.";
  if (error?.status === 409 && error?.message === "BUSY")
    return "На сервере уже выполняется обновление или резервное копирование. Обновите состояние позже.";
  if (error?.status === 409 && error?.message === "EXTERNAL_REFUSED")
    return "Сервер отказал: пакет, Agent или исходный Hub изменились либо не готовы. Обновите состояние и получите новый план.";
  if (action) return "Результат применения неизвестен. SovaGrid обновит состояние, но не повторит команду. Перед новой попыткой проверьте Agent и получите новый план.";
  return "Не удалось проверить внешний Agent. Проверьте подготовленный архив и связь с Hub.";
}

function externalAgentUpdateInvalidate(message = "") {
  const client = externalAgentUpdateClient;
  client.reviewSeq++;
  client.plan = null;
  document.getElementById("externalAgentUpdateConfirm").checked = false;
  if (message) client.notice = message;
}

function externalAgentUpdateRender() {
  const client = externalAgentUpdateClient, status = client.status;
  const ready = Boolean(state.token) && hubCanGlobalAdmin();
  const activeOperation = client.operation && ["accepted", "running", "unknown"].includes(client.operation.phase);
  const badge = document.getElementById("externalAgentUpdateBadge");
  badge.className = "status-badge " + (status?.hub_only && status.idle_endpoint_present ? "ok" :
    status?.hub_only ? "warning" : "waiting");
  badge.textContent = client.loading && !status ? "Проверяем" :
    status?.hub_only && status.idle_endpoint_present ? "Готов к плану" :
      status?.hub_only ? "Нужна проверка" : status ? "Не требуется" : "Нет данных";
  document.getElementById("externalAgentUpdateSummary").textContent = !status ?
    "Состояние внешнего Agent пока недоступно." : !status.hub_only ?
      "На этом сервере нет сохранённого внешнего Agent. Используйте обычное обновление сервера." :
      status.idle_endpoint_present ?
        "Внешний Agent найден. Наличие сокета проверено по метаданным; подтверждение простоя будет получено только при применении." :
        "Внешний Agent найден, но сокет безопасной остановки отсутствует или имеет неверные права. Применение откажет до изменений; для старой установки нужна отдельная миграция.";
  document.getElementById("externalAgentUpdateHubHash").textContent =
    status?.current_hub_manifest_sha256 || "—";
  document.getElementById("externalAgentUpdateAgentHash").textContent =
    status?.external_agent_manifest_sha256 || "—";
  const archive = document.getElementById("externalAgentUpdateArchive");
  archive.disabled = !ready || client.busy;
  const archiveSHA = archive.value.trim().toLowerCase();
  document.getElementById("externalAgentUpdateReload").disabled = !ready || client.loading || client.busy;
  document.getElementById("externalAgentUpdatePreflight").disabled = !ready || client.loading ||
    client.busy || activeOperation || !status?.hub_only || !EXTERNAL_AGENT_SHA.test(archiveSHA);
  const review = document.getElementById("externalAgentUpdateReview");
  review.hidden = !client.plan;
  if (client.plan) {
    const plan = client.plan.preflight;
    document.getElementById("externalAgentUpdatePlanSummary").textContent =
      `Проверено ${plan.candidate_agent_file_count} файлов Agent. Изменится ${plan.source_paths_to_change.length} путей источника и ${plan.metadata_paths_to_change.length} файла состояния.`;
    document.getElementById("externalAgentUpdatePlanWarning").textContent =
      "При применении сервер повторно проверит все отпечатки, lease исходного Hub, простой старого Agent и состояние нового Agent. Операция может временно прервать работу внешнего Agent.";
    document.getElementById("externalAgentUpdateArchiveHash").textContent = client.plan.archive;
    document.getElementById("externalAgentUpdateCandidateHash").textContent = plan.candidate_manifest_sha256;
    document.getElementById("externalAgentUpdateOriginalHash").textContent = plan.external_agent_manifest_sha256;
    document.getElementById("externalAgentUpdateReviewHash").textContent = plan.review_sha256;
    document.getElementById("externalAgentUpdateFiles").textContent =
      [...plan.source_paths_to_change.map((entry) => `${entry.operation}: ${entry.path}`),
        ...plan.metadata_paths_to_change.map((path) => `состояние: ${path}`)].join("\n");
  }
  document.getElementById("externalAgentUpdateApply").disabled = !client.plan || !ready ||
    client.loading || client.busy || activeOperation || !status?.idle_endpoint_present ||
    archiveSHA !== client.plan.archive ||
    status.current_hub_manifest_sha256 !== client.plan.hub ||
    status.external_agent_manifest_sha256 !== client.plan.external ||
    !document.getElementById("externalAgentUpdateConfirm").checked;
  document.getElementById("externalAgentUpdateCancel").disabled = client.busy;
  const operationPanel = document.getElementById("externalAgentUpdateOperation");
  operationPanel.hidden = !client.operation;
  if (client.operation) {
    const labels = { unknown: "Проверяем, был ли запрос принят сервером.",
      accepted: "Запрос принят; ждём запуска обновления.",
      running: "Обновление Agent выполняется.", complete: "Операция завершена.",
      failed: "Операция завершилась ошибкой; проверьте состояние Agent.",
      uncertain: "Итог не подтверждён; требуется проверка состояния Agent." };
    document.getElementById("externalAgentUpdateOperationPhase").textContent =
      labels[client.operation.phase] + (client.operation.error ? ` Код: ${client.operation.error}.` : "");
    document.getElementById("externalAgentUpdateOperationId").textContent = client.operation.request_id;
  }
  document.getElementById("externalAgentUpdateOperationReload").disabled =
    !ready || !client.operation || client.operationLoading;
  document.getElementById("externalAgentUpdateHistoryReload").disabled =
    !ready || client.recentLoading;
  document.getElementById("externalAgentUpdateHistory").textContent = client.recentError ||
    (!client.recentLoaded ? "" :
    client.recent.length ? client.recent.slice(0, 8).map((record) =>
      `${new Date(record.updated_at * 1000).toLocaleString("ru-RU", { timeZone: "UTC" })} UTC · ${EXTERNAL_AGENT_PHASE_LABELS[record.phase]} · ${record.request_id}`
    ).join("\n") : "Операций пока нет.");
  document.getElementById("externalAgentUpdateNotice").textContent = client.notice;
  const error = document.getElementById("externalAgentUpdateError");
  error.textContent = client.error; error.hidden = !client.error;
}

function externalAgentUpdateReset() {
  const client = externalAgentUpdateClient;
  client.generation++;
  clearTimeout(client.pollTimer);
  externalAgentUpdateInvalidate();
  Object.assign(client, { loading: false, busy: false, status: null, error: "",
    notice: "", errorFromAction: false, lastRefresh: 0, operation: null,
    operationExpectedHub: null, operationLoading: false, pollTimer: null, pollStarted: 0,
    recent: [], recentLoaded: false, recentLoading: false, recentError: "" });
  document.getElementById("externalAgentUpdateArchive").value = "";
  externalAgentUpdateRender();
}
globalThis.externalAgentUpdateReset = externalAgentUpdateReset;
globalThis.externalAgentUpdateAccessChanged = () => {
  if (!hubCanGlobalAdmin()) externalAgentUpdateReset();
};

async function externalAgentUpdateRefresh(force = false) {
  const client = externalAgentUpdateClient;
  if (!state.token || !hubCanGlobalAdmin() || client.loading || client.busy) return;
  if (!force && Date.now() - client.lastRefresh < 30000) return;
  const generation = client.generation, token = state.token, base = state.base;
  client.loading = true; client.lastRefresh = Date.now(); externalAgentUpdateRender();
  try {
    const value = externalAgentUpdateStatus(await request("/api/v1/external-agent-update",
      { timeoutMs: 30000 }));
    if (!externalAgentUpdateCurrent(generation, token, base)) return;
    if (client.status && (client.status.current_hub_manifest_sha256 !== value.current_hub_manifest_sha256 ||
        client.status.external_agent_manifest_sha256 !== value.external_agent_manifest_sha256 ||
        client.status.hub_only !== value.hub_only ||
        client.status.idle_endpoint_present !== value.idle_endpoint_present)) {
      const completed = client.operation?.phase === "complete" &&
        client.operationExpectedHub === value.external_agent_manifest_sha256;
      externalAgentUpdateInvalidate(completed ?
        "Внешний Agent обновлён: установленный манифест совпал с подтверждённым пакетом." :
        "Состояние Agent изменилось. Получите новый план перед применением.");
    }
    client.status = value;
    if (!client.errorFromAction) client.error = "";
    if (client.operation?.phase === "complete" && client.operationExpectedHub) {
      if (value.external_agent_manifest_sha256 === client.operationExpectedHub) {
        client.notice = "Внешний Agent обновлён: установленный манифест совпал с подтверждённым пакетом.";
      } else {
        client.error = "Операция завершена, но установленный манифест Agent не совпал с планом. Проверьте состояние сервера.";
        client.errorFromAction = true;
      }
    }
    if (!client.recentLoaded) void externalAgentUpdateRecent();
  } catch (error) {
    if (!externalAgentUpdateCurrent(generation, token, base)) return;
    client.status = null;
    externalAgentUpdateInvalidate();
    if (!client.errorFromAction) client.error = externalAgentUpdateExplain(error);
  } finally {
    if (externalAgentUpdateCurrent(generation, token, base)) {
      client.loading = false; externalAgentUpdateRender();
    }
  }
}
globalThis.externalAgentUpdateRefresh = externalAgentUpdateRefresh;

async function externalAgentUpdateRecent() {
  const client = externalAgentUpdateClient;
  if (!state.token || !hubCanGlobalAdmin() || client.recentLoading) return;
  const generation = client.generation, token = state.token, base = state.base;
  client.recentLoading = true; externalAgentUpdateRender();
  try {
    const value = await request("/api/v1/external-agent-update/operations",
      { timeoutMs: 30000 });
    if (!value || typeof value !== "object" || Array.isArray(value) ||
        Object.keys(value).length !== 1 || !Array.isArray(value.operations) ||
        value.operations.length > 64)
      throw new Error("Hub вернул неверную историю обновлений Agent.");
    const records = value.operations.map((record) => externalAgentUpdateOperationRecord(record));
    if (new Set(records.map((record) => record.request_id)).size !== records.length)
      throw new Error("Hub вернул повторяющиеся операции Agent.");
    if (!externalAgentUpdateCurrent(generation, token, base)) return;
    client.recent = records.sort((a, b) => b.updated_at - a.updated_at);
    client.recentLoaded = true;
    client.recentError = "";
    if (!client.operation && client.recent.length &&
        ["accepted", "running"].includes(client.recent[0].phase)) {
      if (client.plan || client.busy)
        externalAgentUpdateInvalidate("На сервере уже идёт обновление Agent; текущий план сброшен.");
      client.operation = client.recent[0];
      client.pollStarted = Date.now();
      externalAgentUpdateSchedulePoll();
    }
  } catch {
    if (!externalAgentUpdateCurrent(generation, token, base)) return;
    client.recent = [];
    client.recentLoaded = true;
    client.recentError = "История операций пока недоступна.";
  } finally {
    if (externalAgentUpdateCurrent(generation, token, base)) {
      client.recentLoading = false; externalAgentUpdateRender();
    }
  }
}

async function externalAgentUpdatePrepare() {
  const client = externalAgentUpdateClient;
  const archive = document.getElementById("externalAgentUpdateArchive").value.trim().toLowerCase();
  if (!state.token || !hubCanGlobalAdmin() || !client.status?.hub_only || client.busy || client.loading ||
      (client.operation && ["accepted", "running", "unknown"].includes(client.operation.phase)) ||
      !EXTERNAL_AGENT_SHA.test(archive)) return;
  externalAgentUpdateInvalidate();
  const sequence = client.reviewSeq, generation = client.generation,
    token = state.token, base = state.base, snapshot = client.status;
  client.busy = true; client.error = ""; client.errorFromAction = false;
  client.notice = "Проверяем подготовленный пакет и изменения без записи на сервер.";
  externalAgentUpdateRender();
  const body = JSON.stringify({ archive_sha256: archive,
    current_hub_manifest_sha256: snapshot.current_hub_manifest_sha256 });
  try {
    const preview = externalAgentUpdatePreview(await request(
      "/api/v1/external-agent-update/preview", { method: "POST", body, timeoutMs: 90000 }), snapshot);
    if (!externalAgentUpdateCurrent(generation, token, base) || client.reviewSeq !== sequence) return;
    if (!preview.apply_supported) throw new Error("Пакет не поддерживает безопасное обновление внешнего Agent.");
    const preflight = externalAgentUpdatePreflight(await request(
      "/api/v1/external-agent-update/preflight", { method: "POST", body, timeoutMs: 90000 }),
    snapshot, archive);
    if (!externalAgentUpdateCurrent(generation, token, base) || client.reviewSeq !== sequence ||
        client.status !== snapshot ||
        document.getElementById("externalAgentUpdateArchive").value.trim().toLowerCase() !== archive) return;
    client.plan = { archive, hub: snapshot.current_hub_manifest_sha256,
      external: snapshot.external_agent_manifest_sha256, preflight };
    client.notice = snapshot.idle_endpoint_present ?
      "План готов. Проверьте отпечатки и точные пути перед подтверждением." :
      "План готов, но у старого Agent нет проверенного idle-сокета. Применение сейчас недоступно.";
  } catch (error) {
    if (!externalAgentUpdateCurrent(generation, token, base) || client.reviewSeq !== sequence) return;
    client.error = externalAgentUpdateExplain(error);
    client.notice = "";
  } finally {
    if (externalAgentUpdateCurrent(generation, token, base)) {
      client.busy = false; externalAgentUpdateRender();
    }
  }
}

async function externalAgentUpdateApply() {
  const client = externalAgentUpdateClient, plan = client.plan, status = client.status;
  if (!plan || !status || !state.token || !hubCanGlobalAdmin() || client.busy || client.loading ||
      (client.operation && ["accepted", "running", "unknown"].includes(client.operation.phase)) ||
      !status.idle_endpoint_present || !document.getElementById("externalAgentUpdateConfirm").checked ||
      document.getElementById("externalAgentUpdateArchive").value.trim().toLowerCase() !== plan.archive ||
      status.current_hub_manifest_sha256 !== plan.hub ||
      status.external_agent_manifest_sha256 !== plan.external) return;
  let requestId;
  try { requestId = externalAgentUpdateRequestId(); }
  catch (error) { client.error = error.message; externalAgentUpdateRender(); return; }
  const generation = client.generation, token = state.token, base = state.base;
  const body = JSON.stringify({ request_id: requestId, archive_sha256: plan.archive,
    current_hub_manifest_sha256: plan.hub,
    external_agent_manifest_sha256: plan.external,
    review_sha256: plan.preflight.review_sha256, confirmed: true });
  // Reserve the UUID and consume the review before POST. A lost response is
  // reconciled by GET on this UUID; POST is never retried by the browser.
  externalAgentUpdateInvalidate();
  client.operation = { format: 1, request_id: requestId, phase: "unknown",
    created_at: Math.floor(Date.now() / 1000), updated_at: Math.floor(Date.now() / 1000), error: null };
  client.operationExpectedHub = plan.hub;
  client.pollStarted = Date.now();
  client.busy = true; client.error = ""; client.errorFromAction = false;
  client.notice = "Отправляем один запрос на обновление. Его номер останется на экране для проверки результата.";
  externalAgentUpdateRender();
  try {
    const reply = externalAgentUpdateOperationRecord(await request(
      "/api/v1/external-agent-update/apply", { method: "POST", body, timeoutMs: 45000 }), requestId);
    if (!externalAgentUpdateCurrent(generation, token, base)) return;
    client.operation = reply;
    client.notice = "Запрос принят. Проверяем ход операции по её номеру.";
    client.error = "";
  } catch (error) {
    if (!externalAgentUpdateCurrent(generation, token, base)) return;
    client.error = externalAgentUpdateExplain(error, true);
    client.errorFromAction = true;
    client.notice = "Проверяем номер запроса на сервере; повторной отправки не будет.";
  } finally {
    if (externalAgentUpdateCurrent(generation, token, base)) {
      client.busy = false;
      externalAgentUpdateRender();
      await externalAgentUpdatePoll();
    }
  }
}

function externalAgentUpdateSchedulePoll() {
  const client = externalAgentUpdateClient;
  clearTimeout(client.pollTimer);
  if (!client.operation || !["accepted", "running", "unknown"].includes(client.operation.phase) ||
      !state.token || !hubCanGlobalAdmin()) return;
  if (Date.now() - client.pollStarted >= 20 * 60 * 1000) {
    client.operation = { ...client.operation, phase: "uncertain", error: "STATUS_TIMEOUT" };
    client.error = "Долгое обновление не удалось подтвердить. Проверьте состояние Agent и журнал операции; команда не будет повторена.";
    client.errorFromAction = true;
    externalAgentUpdateRender();
    void externalAgentUpdateRefresh(true);
    return;
  }
  client.pollTimer = setTimeout(() => { void externalAgentUpdatePoll(); }, 4000);
}

async function externalAgentUpdatePoll() {
  const client = externalAgentUpdateClient, operation = client.operation;
  if (!operation || client.operationLoading || !state.token || !hubCanGlobalAdmin()) return;
  const generation = client.generation, token = state.token, base = state.base;
  client.operationLoading = true; externalAgentUpdateRender();
  try {
    const record = externalAgentUpdateOperationRecord(await request(
      `/api/v1/external-agent-update/operations/${operation.request_id}`,
      { timeoutMs: 30000 }), operation.request_id);
    if (!externalAgentUpdateCurrent(generation, token, base) ||
        client.operation?.request_id !== operation.request_id) return;
    client.operation = record;
    client.error = "";
    client.errorFromAction = false;
    if (record.phase === "complete") {
      client.notice = "Операция завершена. Проверяем установленную версию Agent.";
      client.lastRefresh = 0;
      void externalAgentUpdateRefresh(true);
    } else if (record.phase === "failed" || record.phase === "uncertain") {
      client.error = record.phase === "failed" ?
        "Операция завершилась ошибкой. Проверьте состояние Agent и получите новый план перед повторной попыткой." :
        "Результат операции не подтверждён. Проверьте состояние Agent перед новым планом.";
      client.errorFromAction = true;
      client.notice = "";
      client.lastRefresh = 0;
      void externalAgentUpdateRefresh(true);
    } else {
      client.notice = record.phase === "accepted" ?
        "Запрос принят; ожидаем запуска обновления." : "Обновление внешнего Agent выполняется.";
    }
  } catch (error) {
    if (!externalAgentUpdateCurrent(generation, token, base) ||
        client.operation?.request_id !== operation.request_id) return;
    client.error = "Пока не удалось прочитать состояние операции. Повторная отправка обновления не выполняется.";
    client.errorFromAction = true;
  } finally {
    if (externalAgentUpdateCurrent(generation, token, base) &&
        client.operation?.request_id === operation.request_id) {
      client.operationLoading = false;
      externalAgentUpdateRender();
      externalAgentUpdateSchedulePoll();
    }
  }
}

document.getElementById("externalAgentUpdateArchive").addEventListener("input", () => {
  externalAgentUpdateInvalidate();
  externalAgentUpdateClient.error = "";
  externalAgentUpdateClient.errorFromAction = false;
  externalAgentUpdateClient.notice = "";
  externalAgentUpdateRender();
});
document.getElementById("externalAgentUpdateReload").addEventListener("click", () => {
  externalAgentUpdateClient.error = "";
  externalAgentUpdateClient.errorFromAction = false;
  void externalAgentUpdateRefresh(true);
});
document.getElementById("externalAgentUpdatePreflight").addEventListener("click", () => {
  void externalAgentUpdatePrepare();
});
document.getElementById("externalAgentUpdateConfirm").addEventListener("change", externalAgentUpdateRender);
document.getElementById("externalAgentUpdateCancel").addEventListener("click", () => {
  externalAgentUpdateInvalidate(); externalAgentUpdateClient.notice = "План отменён.";
  externalAgentUpdateRender();
});
document.getElementById("externalAgentUpdateApply").addEventListener("click", () => {
  void externalAgentUpdateApply();
});
document.getElementById("externalAgentUpdateOperationReload").addEventListener("click", () => {
  void externalAgentUpdatePoll();
});
document.getElementById("externalAgentUpdateHistoryReload").addEventListener("click", () => {
  void externalAgentUpdateRecent();
});
externalAgentUpdateRender();

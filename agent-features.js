/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// Reuse the reviewed Add Server SSH route, including its separate jump pins.
// SSH secrets live only in its visible inputs and per-request objects.
const agentFeatures = { active: false, generation: 0, session: 0, token: null, current: null,
  plan: null, selectionKey: "", selected: "", identity: null, servers: null };
const AGENT_FEATURE_FLAGS = ["commands", "terminal", "files"];
const AGENT_FEATURE_LABELS = { commands: "Команды Agent", terminal: "Терминал", files: "Файлы" };
const AGENT_FEATURE_UUID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/;
const afElement = (id) => document.getElementById(id);

function agentFeaturesFlags(value) {
  return !!value && typeof value === "object" && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...AGENT_FEATURE_FLAGS].sort()) &&
    AGENT_FEATURE_FLAGS.every((key) => typeof value[key] === "boolean");
}
function agentFeaturesDesired() {
  return Object.fromEntries(AGENT_FEATURE_FLAGS.map((key) => [key,
    afElement("agentFeatures" + key[0].toUpperCase() + key.slice(1)).checked]));
}
function agentFeaturesDependencies(value) { return value.commands || (!value.terminal && !value.files); }
function agentFeaturesSameFlags(left, right) {
  return agentFeaturesFlags(left) && agentFeaturesFlags(right) &&
    AGENT_FEATURE_FLAGS.every((key) => left[key] === right[key]);
}
function agentFeaturesAllowed() { return serverSetupAllowed(); }
function agentFeaturesServer() {
  return agentFeatures.servers?.find((row) => row.id === afElement("agentFeaturesServer").value) || null;
}
function agentFeaturesError(message = "") {
  if (message) showError(afElement("agentFeaturesError"), message);
  else clearError(afElement("agentFeaturesError"));
}
function agentFeaturesClearPlan() {
  agentFeatures.plan = null;
  afElement("agentFeaturesConfirm").checked = false;
  afElement("agentFeaturesReview").hidden = true;
}
function agentFeaturesInvalidate() {
  agentFeatures.generation++;
  agentFeatures.current = null;
  agentFeatures.identity = null;
  agentFeaturesClearPlan();
  afElement("agentFeaturesNotice").textContent = "";
  agentFeaturesError();
}
function agentFeaturesReset() {
  agentFeatures.session++;
  agentFeaturesInvalidate();
  agentFeatures.active = false;
  agentFeatures.token = null;
  agentFeatures.selectionKey = "";
  agentFeatures.selected = "";
  agentFeatures.servers = null;
  afElement("agentFeaturesPanel").hidden = true;
  afElement("addServerHeading").textContent = "Добавить Ubuntu-сервер";
  afElement("addServerEyebrow").textContent = "Новый сервер";
  afElement("serverSetupTabs").hidden = false;
  afElement("serverSetupIntro").hidden = false;
  afElement("serverSetupDirectTerminalButton").hidden = false;
  afElement("serverSetupStatusButton").hidden = false;
}
function agentFeaturesAccessChanged() {
  if (agentFeatures.active && (!agentFeaturesAllowed() || state.token !== agentFeatures.token)) {
    agentFeaturesReset();
    serverSetupInvalidate();
    serverSetupClearSecrets();
    globalThis.sovagridDirectSSH?.clearCredentials?.();
    if (afElement("addServerDialog").open) afElement("addServerDialog").close();
  }
  agentFeaturesRender();
}
function agentFeaturesRoute() {
  const reviewed = serverSetup.reviewed;
  if (!reviewed || serverSetup.changedPin || !afElement("serverSetupTrust").checked) return null;
  let target;
  try { target = serverSetupTarget(); } catch { return null; }
  if (target.host !== reviewed.host || target.port !== reviewed.port) return null;
  const viaJump = Boolean(globalThis.sovagridDirectSSH?.jumpEnabled?.());
  const jump = viaJump ? globalThis.sovagridDirectSSH?.reviewedJump?.() : null;
  if (viaJump && (!jump || !reviewed.viaJump || reviewed.jumpHost !== jump.host ||
      reviewed.jumpPort !== jump.port || reviewed.jumpFingerprint !== jump.fingerprint ||
      !serverSetupHostKeyBlobValid(reviewed.host_key_blob))) return null;
  if (!viaJump && reviewed.viaJump) return null;
  return { reviewed: { ...reviewed }, jump, server_id: afElement("agentFeaturesServer").value,
    username: afElement("serverSetupUsername").value.trim(),
    method: afElement("serverSetupAuthKey").checked ? "private_key" : "password" };
}
function agentFeaturesSameRoute(left, right = agentFeaturesRoute()) {
  if (!left || !right) return false;
  return left.server_id === right.server_id && left.username === right.username && left.method === right.method &&
    left.reviewed.host === right.reviewed.host && left.reviewed.port === right.reviewed.port &&
    left.reviewed.fingerprint === right.reviewed.fingerprint &&
    left.jump?.host === right.jump?.host && left.jump?.port === right.jump?.port &&
    left.jump?.fingerprint === right.jump?.fingerprint;
}
function agentFeaturesRender() {
  const allowed = agentFeaturesAllowed();
  for (const element of document.querySelectorAll("[data-agent-features-entry]")) {
    element.hidden = !allowed;
    element.disabled = !selectedServer();
  }
  afElement("serverSetupAgentFeaturesButton").hidden = !allowed || serverSetup.job?.phase !== "active";
  afElement("agentFeaturesPanel").hidden = !agentFeatures.active;
  if (!agentFeatures.active) return;
  afElement("addServerHeading").textContent = "Настроить разрешения Agent";
  afElement("addServerEyebrow").textContent = "Доступ к серверу";
  afElement("serverSetupTabs").hidden = true;
  afElement("serverSetupIntro").hidden = true;
  afElement("serverSetupRecovery").hidden = true;
  afElement("serverSetupResult").hidden = true;
  afElement("serverSetupInstallPanel").hidden = true;
  afElement("serverSetupJobReview").hidden = true;
  afElement("serverSetupDirectTerminalButton").hidden = true;
  afElement("serverSetupStatusButton").hidden = true;
  const select = afElement("agentFeaturesServer");
  const rows = agentFeatures.servers || [];
  const selectionKey = JSON.stringify(rows.map((row) => [row.id, row.name]));
  if (selectionKey !== agentFeatures.selectionKey) {
    const selected = agentFeatures.selected || select.value;
    const prompt = document.createElement("option"); prompt.value = ""; prompt.textContent = "Выберите сервер";
    select.replaceChildren(prompt, ...rows.map((row) => {
      const option = document.createElement("option"); option.value = row.id; option.textContent = row.name || row.id; return option;
    }));
    select.value = rows.some((row) => row.id === selected) ? selected : "";
    agentFeatures.selectionKey = selectionKey;
  }
  const route = agentFeaturesRoute();
  const ready = allowed && state.token === agentFeatures.token && route && agentFeaturesServer() && AGENT_FEATURE_UUID.test(route.server_id);
  const busy = serverSetup.busy;
  const desired = agentFeaturesDesired();
  select.disabled = busy;
  afElement("agentFeaturesRead").disabled = busy || !ready;
  afElement("agentFeaturesRead").textContent = serverSetup.phase === "features_read" ? "Проверяем Agent…" : "2. Проверить Agent и текущие разрешения";
  afElement("agentFeaturesOptions").hidden = !agentFeatures.current;
  for (const key of AGENT_FEATURE_FLAGS) afElement("agentFeatures" + key[0].toUpperCase() + key.slice(1)).disabled = busy;
  afElement("agentFeaturesDependency").hidden = agentFeaturesDependencies(desired);
  afElement("agentFeaturesPreview").disabled = busy || !ready || !agentFeatures.current || !agentFeaturesDependencies(desired);
  if (agentFeatures.plan && !agentFeaturesSameRoute(agentFeatures.plan.route)) agentFeaturesClearPlan();
  const plan = agentFeatures.plan;
  const validPlan = plan && agentFeaturesSameRoute(plan.route) && agentFeaturesSameFlags(plan.reply.desired, desired);
  afElement("agentFeaturesReview").hidden = !validPlan;
  afElement("agentFeaturesConfirm").disabled = busy || !validPlan;
  afElement("agentFeaturesApply").disabled = busy || !validPlan || !plan.reply.can_apply ||
    !plan.reply.change_required || !afElement("agentFeaturesConfirm").checked;
  afElement("agentFeaturesApply").textContent = serverSetup.phase === "features_apply" ? "Применяем и проверяем Agent…" : "4. Применить разрешения";
}
function agentFeaturesOpen(serverId = state.selectedId, target = null) {
  if (!agentFeaturesAllowed()) return;
  if (!afElement("addServerDialog").open) afElement("addServerDialog").showModal();
  serverSetupReset();
  agentFeatures.active = true;
  agentFeatures.token = state.token;
  agentFeatures.selected = AGENT_FEATURE_UUID.test(serverId || "") ? serverId : "";
  if (target) {
    afElement("serverSetupHost").value = target.host;
    afElement("serverSetupPort").value = String(target.port);
    afElement("serverSetupUsername").value = target.username;
  }
  serverSetupRender();
  afElement("serverSetupHost").focus?.();
  return agentFeaturesLoadServers();
}
async function agentFeaturesLoadServers() {
  const session = agentFeatures.session;
  const token = agentFeatures.token;
  afElement("agentFeaturesNotice").textContent = "Проверяем список отдельных Agent…";
  try {
    const reply = await request("/api/v1/agent-management");
    if (!agentFeatures.active || session !== agentFeatures.session || state.token !== token || !agentFeaturesAllowed()) return;
    if (!reply || typeof reply !== "object" || Array.isArray(reply) ||
        JSON.stringify(Object.keys(reply).sort()) !== JSON.stringify(["servers", "truncated"]) ||
        typeof reply.truncated !== "boolean" || !Array.isArray(reply.servers) || reply.servers.length > 256) throw new Error("INVALID_RESPONSE");
    if (reply.truncated) throw new Error("SERVER_LIST_LIMIT");
    const seen = new Set();
    for (const row of reply.servers) {
      if (!row || typeof row !== "object" || Array.isArray(row) ||
          JSON.stringify(Object.keys(row).sort()) !== JSON.stringify(["id", "name"]) ||
          !AGENT_FEATURE_UUID.test(row.id || "") || seen.has(row.id) || typeof row.name !== "string" ||
          [...row.name].length < 1 || [...row.name].length > 80 || row.name.trim() !== row.name ||
          /[\x00-\x1f\x7f-\x9f]/.test(row.name)) throw new Error("INVALID_RESPONSE");
      seen.add(row.id);
    }
    agentFeatures.servers = reply.servers.map((row) => ({ id: row.id, name: row.name }));
    afElement("agentFeaturesNotice").textContent = reply.servers.length ?
      "В списке только отдельные Agent, подключённые через SSH. Выберите Agent и проверьте его адрес." :
      "Отдельных Agent пока нет. Подключите дополнительный Ubuntu-сервер через «Добавить сервер → SSH», затем откройте этот мастер снова.";
  } catch (error) {
    if (agentFeatures.active && session === agentFeatures.session && state.token === token) {
      agentFeatures.servers = [];
      agentFeaturesError(error.message === "SERVER_LIST_LIMIT" ? "Мастер поддерживает до 256 отдельных Agent. Список не был усечён для изменения разрешений." : agentFeaturesExplain(error));
    }
  } finally { if (agentFeatures.active && session === agentFeatures.session) agentFeaturesRender(); }
}
async function agentFeaturesAfterEnrollment() {
  if (serverSetup.job?.phase !== "active" || !agentFeaturesAllowed()) return;
  const token = state.token;
  const serverId = serverSetup.job.server_id;
  let target = null;
  try { target = { ...serverSetupTarget(), username: afElement("serverSetupUsername").value.trim() }; } catch { /* User chooses a route afresh. */ }
  await refresh();
  if (state.token === token && agentFeaturesAllowed()) agentFeaturesOpen(serverId || "", target);
}
function agentFeaturesReply(value, route, action, desired) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const common = ["protocol", "action", "scope", "host", "port", "host_key_fingerprint", "server_id", "kind",
    "current", "desired", "hub_enabled", "hub_revision", "source_manifest_sha256"];
  const fields = action === "preview" ? [...common, "can_apply", "change_required", "recovery_required", "pending_features",
    "review_sha256", "temporary_writes", "activation_writes"] : [...common, "applied", "changed", "fresh_metric_verified", "cleanup_required"];
  if (route.jump) fields.push("jump_host", "jump_port", "jump_host_key_fingerprint");
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(fields.sort()) || value.protocol !== 1 ||
      value.action !== action || value.scope !== "entered_target" || value.kind !== "agent_only" ||
      value.host !== route.reviewed.host || value.port !== route.reviewed.port ||
      value.host_key_fingerprint !== route.reviewed.fingerprint || value.server_id !== route.server_id ||
      !agentFeaturesFlags(value.current) || !agentFeaturesFlags(value.desired) || typeof value.hub_enabled !== "boolean" ||
      !Number.isSafeInteger(value.hub_revision) || value.hub_revision < 0 ||
      !/^[0-9a-f]{64}$/.test(value.source_manifest_sha256 || "")) return false;
  if (route.jump && (value.jump_host !== route.jump.host || value.jump_port !== route.jump.port ||
      value.jump_host_key_fingerprint !== route.jump.fingerprint)) return false;
  if (action === "preview") {
    return typeof value.can_apply === "boolean" && typeof value.change_required === "boolean" &&
      typeof value.recovery_required === "boolean" &&
      (value.pending_features === null || agentFeaturesFlags(value.pending_features)) &&
      value.temporary_writes === true && value.activation_writes === false &&
      (desired === null ? value.review_sha256 === null && value.can_apply === false &&
        agentFeaturesSameFlags(value.desired, value.pending_features || value.current) :
        /^[0-9a-f]{64}$/.test(value.review_sha256 || "") && agentFeaturesSameFlags(value.desired, desired));
  }
  return value.applied === true && typeof value.changed === "boolean" && value.fresh_metric_verified === true &&
    value.cleanup_required === false && value.hub_enabled === desired.commands &&
    agentFeaturesSameFlags(value.current, desired) && agentFeaturesSameFlags(value.desired, desired);
}
function agentFeaturesExplain(error, apply = false) {
  const messages = { AGENT_NOT_ENROLLED: "Этот мастер работает с отдельным Agent, установленным через SSH из панели или Connect. Полная установка Hub здесь не изменяется.",
    ROOT_REQUIRED: "Нужен root или пользователь с уже разрешённым sudo без пароля. Пароль sudo не используется.",
    IDENTITY_MISMATCH: "SSH-сервер не подтвердил принадлежность выбранному Agent. Проверьте сервер в списке и адрес SSH.",
    SERVER_MISMATCH: "На SSH-сервере найден другой Agent. Проверьте выбор сервера и адрес.",
    REVIEW_CHANGED: "Состояние изменилось. Проверьте Agent и получите новый план перед подтверждением.",
    STALE_PREVIEW: "Состояние Agent или допуск Hub изменились. Проверьте Agent и получите новый план перед подтверждением.",
    STALE_REVISION: "Допуск Hub изменился. Проверьте Agent и получите новый план.",
    RECOVERY_REQUIRED: "На сервере есть незавершённое изменение. Проверьте Agent снова и подтвердите план восстановления.",
    INVALID_RESPONSE: "Hub вернул несовместимый ответ. Обновите серверную часть перед изменением разрешений.",
    INVALID_USERNAME: "Введите корректное имя SSH-пользователя.", INVALID_KEY: "Выберите SSH-ключ до 64 КиБ.",
    KEY_NOT_SAVED: "Сначала сохраните созданный приватный ключ.", FILE_READ_FAILED: "Не удалось прочитать выбранный SSH-ключ.",
    PASSWORD_INVALID: "Введите пароль SSH длиной до 1024 символов." };
  if (error?.status === 404) return "Этот Hub ещё не поддерживает настройку разрешений Agent через Web. Обновите серверную часть.";
  if (error?.message === "SSH_TIMEOUT" || error?.message === "APPLY_UNCERTAIN") return apply ?
    "Ответ потерян. Разрешения могли измениться: сначала проверьте Agent снова. Новый запуск требует нового плана." :
    "Проверка не завершилась. Введите SSH-данные и проверьте Agent снова.";
  return messages[error?.message] || serverSetupExplain(error);
}
function agentFeaturesShowCurrent(reply) {
  afElement("agentFeaturesCurrent").textContent = AGENT_FEATURE_FLAGS.map((key) =>
    `${AGENT_FEATURE_LABELS[key]}: ${reply.current[key] ? "включены" : "выключены"}`).join(" · ") +
    ` · Допуск Hub: ${reply.hub_enabled ? "включён" : "выключен"}.`;
}
function agentFeaturesShowPlan(reply, route) {
  agentFeatures.plan = { reply, route };
  const server = agentFeaturesServer();
  afElement("agentFeaturesScope").textContent = `${server?.name || route.server_id} · SSH ${route.reviewed.host}:${route.reviewed.port}`;
  const lines = AGENT_FEATURE_FLAGS.map((key) => `${AGENT_FEATURE_LABELS[key]}: ${reply.current[key] ? "включено" : "выключено"} → ${reply.desired[key] ? "включено" : "выключено"}`);
  lines.push(`Допуск команд в Hub: ${reply.hub_enabled ? "включён" : "выключен"} → ${reply.desired.commands ? "включён" : "выключен"}`);
  afElement("agentFeaturesChanges").replaceChildren(...lines.map((text) => {
    const item = document.createElement("li"); item.textContent = text; return item;
  }));
  afElement("agentFeaturesConfirmText").textContent = reply.desired.commands ?
    "Я проверил этот сервер и разрешаю произвольные команды на Agent и их допуск в Hub по этому плану" :
    "Я проверил этот сервер и подтверждаю отключение команд и указанный план разрешений";
  afElement("agentFeaturesConfirm").checked = false;
  afElement("agentFeaturesNotice").textContent = !reply.change_required ? "Выбранные разрешения уже установлены." :
    reply.recovery_required ? "План также завершит незавершённую смену разрешений. Сверьте параметры перед подтверждением." :
      "План готов. До подтверждения разрешения не изменены.";
}
async function agentFeaturesRequest(action, desired) {
  if (!agentFeatures.active || serverSetup.busy || !agentFeaturesAllowed() || state.token !== agentFeatures.token) return;
  const route = agentFeaturesRoute();
  if (!route || !agentFeaturesServer() || !AGENT_FEATURE_UUID.test(route.server_id)) { agentFeaturesError("Выберите отдельный Agent в Hub и сверьте SSH-ключ выбранного адреса."); return; }
  const plan = agentFeatures.plan;
  if (action === "apply" && (!plan || !afElement("agentFeaturesConfirm").checked || !plan.reply.can_apply ||
      !plan.reply.change_required || !agentFeaturesSameRoute(plan.route) || !agentFeaturesSameFlags(plan.reply.desired, desired))) return;
  if (desired !== null && (!agentFeaturesFlags(desired) || !agentFeaturesDependencies(desired))) {
    agentFeaturesError("Для терминала и файлов требуется явно разрешить команды."); return;
  }
  const generation = ++agentFeatures.generation;
  const seq = ++serverSetup.seq;
  const token = state.token;
  serverSetup.busy = true;
  serverSetup.phase = action === "apply" ? "features_apply" : desired === null ? "features_read" : "features_preview";
  agentFeaturesError();
  serverSetupRender();
  let credentials;
  const current = () => agentFeatures.active && agentFeatures.generation === generation && seq === serverSetup.seq &&
    state.token === token && agentFeaturesAllowed() && afElement("addServerDialog").open && agentFeaturesSameRoute(route);
  try {
    credentials = await serverSetupReadCredentials(seq, route.reviewed, { rootOnly: false, clear: false });
    if (route.jump) {
      credentials.jump = await globalThis.sovagridDirectSSH.installJumpCredentials(seq, route.jump, { clear: false });
      credentials.host_key_blob = route.reviewed.host_key_blob;
    }
    if (!current()) throw new Error("STALE_REQUEST");
    const payload = { ...credentials, server_id: route.server_id, features: desired };
    if (action === "apply") Object.assign(payload, { expected_review_sha256: plan.reply.review_sha256, confirm: true });
    const reply = await serverSetupApi(`/api/v1/browser-ssh/agent-features/${action}`, payload, 510000, seq);
    if (!current()) return;
    if (!agentFeaturesReply(reply, route, action === "apply" ? "applied" : "preview", desired)) throw new Error("INVALID_RESPONSE");
    serverSetupSavePin(route.reviewed.host, route.reviewed.port, route.reviewed.fingerprint);
    agentFeatures.current = reply;
    agentFeatures.identity = route;
    agentFeaturesShowCurrent(reply);
    if (action === "apply") {
      agentFeaturesClearPlan();
      serverSetupClearSecrets();
      globalThis.sovagridDirectSSH?.clearCredentials?.();
      afElement("agentFeaturesNotice").textContent = "Разрешения применены. Agent перезапущен, подтвердил новые метрики и параметры из плана.";
      void refresh();
    } else if (desired === null) {
      agentFeaturesClearPlan();
      for (const key of AGENT_FEATURE_FLAGS) afElement("agentFeatures" + key[0].toUpperCase() + key.slice(1)).checked = reply.desired[key];
      afElement("agentFeaturesNotice").textContent = reply.recovery_required ?
        "Найдена незавершённая смена разрешений. Предложены её параметры: проверьте их и запросите новый план." :
        "Agent проверен. Выберите разрешения и посмотрите план перед применением.";
    } else agentFeaturesShowPlan(reply, route);
  } catch (error) {
    if (current()) {
      agentFeaturesClearPlan();
      serverSetupClearSecrets();
      globalThis.sovagridDirectSSH?.clearCredentials?.();
      if (error.message === "HOST_KEY_CHANGED") serverSetupInvalidate();
      agentFeaturesError(agentFeaturesExplain(error, action === "apply"));
    }
  } finally {
    if (credentials) {
      for (const key of ["password", "private_key", "passphrase"]) credentials[key] = "";
      if (credentials.jump) for (const key of ["password", "private_key", "passphrase"]) credentials.jump[key] = "";
    }
    if (seq === serverSetup.seq) { serverSetup.busy = false; serverSetup.phase = null; serverSetupRender(); }
  }
}

for (const element of document.querySelectorAll("[data-agent-features-entry]")) element.addEventListener("click", () => agentFeaturesOpen());
afElement("serverSetupAgentFeaturesButton").addEventListener("click", () => { void agentFeaturesAfterEnrollment(); });
afElement("agentFeaturesServer").addEventListener("change", () => {
  agentFeatures.selected = afElement("agentFeaturesServer").value;
  agentFeaturesInvalidate(); agentFeaturesRender();
});
for (const key of AGENT_FEATURE_FLAGS) afElement("agentFeatures" + key[0].toUpperCase() + key.slice(1)).addEventListener("change", () => {
  agentFeatures.generation++;
  agentFeaturesClearPlan(); agentFeaturesRender();
});
afElement("agentFeaturesRead").addEventListener("click", () => { void agentFeaturesRequest("preview", null); });
afElement("agentFeaturesPreview").addEventListener("click", () => { void agentFeaturesRequest("preview", agentFeaturesDesired()); });
afElement("agentFeaturesConfirm").addEventListener("change", agentFeaturesRender);
afElement("agentFeaturesApply").addEventListener("click", () => { void agentFeaturesRequest("apply", agentFeaturesDesired()); });
globalThis.agentFeaturesActive = () => agentFeatures.active;
globalThis.agentFeaturesRead = () => agentFeaturesRequest("preview", null);
globalThis.agentFeaturesRender = agentFeaturesRender;
globalThis.agentFeaturesInvalidate = agentFeaturesInvalidate;
globalThis.agentFeaturesReset = agentFeaturesReset;
globalThis.agentFeaturesAccessChanged = agentFeaturesAccessChanged;
agentFeaturesRender();

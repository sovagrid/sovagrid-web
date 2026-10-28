/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

const containerAction = { generation: 0, serverId: null, targets: new Map(),
  control: null, receivedAt: 0, busy: false, pending: null, jobId: null, confirmation: null };
const CONTAINER_ACTION_ID = /^[0-9a-f]{64}$/;
const CONTAINER_ACTION_JOB = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CONTAINER_ACTION_TERMINAL = new Set(["succeeded", "failed", "timed_out", "output_limited", "cancelled"]);
const CONTAINER_ACTION_STATES = new Set(["created", "running", "paused", "restarting", "removing", "exited", "dead"]);
const CONTAINER_ACTION_LABELS = { start: "Запустить", stop: "Остановить", restart: "Перезапустить" };
const CONTAINER_ACTION_PROTECTED = ["sovagrid", "amnezia", "docker", "containerd", "wireguard",
  "openvpn", "tailscale", "xray", "sing-box"];

function containerActionProtected(name, image) {
  const parts = String(image).toLowerCase().split("/");
  if (parts.length > 1 && (parts[0].includes(".") || parts[0].includes(":") || parts[0] === "localhost")) {
    parts.shift();
  }
  return [String(name).toLowerCase(), ...parts.map((part) => part.split(/[:@]/, 1)[0])]
    .some((part) => CONTAINER_ACTION_PROTECTED.some((prefix) => part.startsWith(prefix)) ||
      part.includes("tunnel") || part.includes("ssh"));
}

function containerActionClearProof(message = "Контейнер ещё не проверен.") {
  containerAction.control = null;
  containerAction.receivedAt = 0;
  $("containerActionStatus").textContent = message;
  clearError($("containerActionError"));
}

function containerActionReset() {
  containerAction.generation++;
  Object.assign(containerAction, { serverId: null, targets: new Map(), control: null,
    receivedAt: 0, busy: false, pending: null, jobId: null, confirmation: null });
  if ($("containerActionDialog").open) $("containerActionDialog").close();
  $("containerActionTarget").replaceChildren();
  $("containerActionTarget").value = "";
  containerActionClearProof();
  clearError($("containerActionDialogError"));
  containerActionRender();
}
globalThis.containerActionReset = containerActionReset;

function containerActionSelectedServer(serverId) {
  if (String(containerAction.serverId) !== String(serverId)) {
    containerActionReset();
    containerAction.serverId = serverId;
  }
}
globalThis.containerActionSelectedServer = containerActionSelectedServer;

function containerActionAccessChanged() {
  const server = state.servers.find((item) => String(item.id) === String(state.selectedId));
  if (!hubCanAdmin(server)) containerActionReset();
}
globalThis.containerActionAccessChanged = containerActionAccessChanged;

// Hub uses its own receipt time for the authoritative freshness check. Agent
// clock skew cannot grant an action, but an incomplete inventory can hide a
// protected target, so it is never offered here.
function containerActionReady(snapshot, server) {
  if (!server || !hubCanAdmin(server) || !server.online || !server.remote_commands_enabled ||
      !snapshot || snapshot.version !== 1 || !Number.isSafeInteger(snapshot.collected_at) ||
      snapshot.collected_at < 1 || snapshot.collected_at > 253402300799 ||
      !Array.isArray(snapshot.engines) || snapshot.engines.length !== 2) return false;
  const docker = snapshot.engines[0], podman = snapshot.engines[1];
  return docker?.engine === "docker" && docker.source_status === "ok" &&
    docker.truncated === false && Array.isArray(docker.containers) && docker.containers.length <= 12 &&
    podman?.engine === "podman" && ["ok", "unavailable"].includes(podman.source_status) &&
    typeof podman.truncated === "boolean" && Array.isArray(podman.containers) &&
    podman.containers.length <= 12;
}

function containerActionTarget() {
  return containerAction.targets.get($("containerActionTarget").value) || null;
}

function containerActionCan(action, target = containerActionTarget()) {
  const client = containerAction;
  const server = state.servers.find((item) => String(item.id) === String(client.serverId));
  const snapshot = server?.latest?.details?.containers;
  const observed = containerActionReady(snapshot, server) && target &&
    snapshot.engines[0].containers.find((item) => item?.id === target.id);
  const proof = client.control;
  return Boolean(target && server && hubCanAdmin(server) && server.online &&
    server.remote_commands_enabled && state.view === "overview" && !document.hidden && !client.busy &&
    observed && observed.name === target.name && observed.image === target.image &&
    observed.state === target.state &&
    proof?.source_status === "ok" && proof.engine === "docker" && proof.id === target.id &&
    Date.now() - client.receivedAt < 85000 &&
    (action === "start" ? ["created", "exited"].includes(proof.state) : proof.state === "running"));
}

function containerActionRender() {
  const target = containerActionTarget();
  const server = state.servers.find((item) => String(item.id) === String(containerAction.serverId));
  const allowed = Boolean(target && server && hubCanAdmin(server) && server.online &&
    server.remote_commands_enabled && state.view === "overview" && !document.hidden);
  $("containerActionTarget").disabled = !allowed || containerAction.busy;
  $("containerActionCheck").disabled = !allowed || containerAction.busy;
  for (const action of Object.keys(CONTAINER_ACTION_LABELS)) {
    $("containerAction" + action[0].toUpperCase() + action.slice(1)).disabled =
      !containerActionCan(action, target);
  }
  const checked = containerAction.control?.source_status === "ok" &&
    containerAction.control.id === target?.id && Date.now() - containerAction.receivedAt < 85000;
  $("containerActionBadge").textContent = checked ? "Проверено" : allowed ? "Нужна проверка" : "Нет доступа";
  $("containerActionBadge").className = `status-badge${checked ? "" : " waiting"}`;
  if (containerAction.control && !checked && !containerAction.busy) {
    $("containerActionStatus").textContent = "Проверка устарела. Проверьте контейнер заново.";
  }
}

function containerActionRenderInventory(snapshot, server) {
  containerActionSelectedServer(server?.id ?? null);
  const admin = hubCanAdmin(server);
  $("containerActionPanel").hidden = !admin;
  if (!admin) { containerActionReset(); return; }
  const targets = new Map();
  if (containerActionReady(snapshot, server)) for (const item of snapshot.engines[0].containers) {
    if (typeof item?.id !== "string" || !CONTAINER_ACTION_ID.test(item.id) ||
        typeof item.name !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$/.test(item.name) ||
        typeof item.image !== "string" || !item.image || item.image.length > 160 ||
        !CONTAINER_ACTION_STATES.has(item.state) || containerActionProtected(item.name, item.image)) continue;
    targets.set(item.id, { id: item.id, name: item.name, image: item.image, state: item.state });
  }
  const previous = $("containerActionTarget").value;
  const selected = targets.has(previous) ? previous : targets.keys().next().value || "";
  const old = containerAction.targets.get(selected), current = targets.get(selected);
  if (previous !== selected || !old || old.name !== current?.name ||
      old.image !== current?.image || old.state !== current?.state) {
    containerAction.generation++;
    containerAction.pending = null;
    containerAction.jobId = null;
    containerAction.busy = false;
    containerActionClearProof(selected ? "Проверьте состояние выбранного контейнера." : "Доступных контейнеров нет.");
  }
  const selector = $("containerActionTarget");
  selector.replaceChildren();
  for (const item of targets.values()) {
    const option = document.createElement("option");
    option.value = item.id;
    option.textContent = `${item.name} · ${item.id.slice(0, 12)}`;
    selector.append(option);
  }
  selector.value = selected;
  containerAction.targets = targets;
  $("containerActionHint").textContent = !server?.online ? "Agent не на связи." :
    !server.remote_commands_enabled ? "Сначала разрешите команды для сервера." :
      !containerActionReady(snapshot, server) ? "Нужен полный снимок Docker от работающего Agent." :
        !targets.size ? "Обычных Docker-контейнеров нет; системные контейнеры защищены." :
          "Выберите контейнер. Hub и Agent повторно проверят список и отдельную локальную политику.";
  containerActionRender();
}
globalThis.containerActionRenderInventory = containerActionRenderInventory;

function containerActionCurrent(generation, serverId, id, token, base) {
  const server = state.servers.find((item) => String(item.id) === String(serverId));
  return containerAction.generation === generation && Boolean(token) &&
    state.token === token && state.base === base && state.view === "overview" &&
    !document.hidden && String(state.selectedId) === String(serverId) &&
    String(containerAction.serverId) === String(serverId) &&
    $("containerActionTarget").value === id && containerAction.targets.has(id) &&
    Boolean(server && hubCanAdmin(server) && server.online && server.remote_commands_enabled);
}

function containerActionValidateControl(reply, id) {
  const value = reply?.control;
  if (!value || value.engine !== "docker" || value.id !== id ||
      !["ok", "unavailable"].includes(value.source_status) ||
      (value.source_status === "ok" && (!CONTAINER_ACTION_STATES.has(value.state) ||
        !Number.isSafeInteger(value.observed_at) || value.observed_at < 1)) ||
      (value.source_status === "unavailable" && (value.state !== null || value.observed_at !== null))) {
    throw new Error("Hub вернул неверное состояние контейнера.");
  }
  return value;
}

async function containerActionQueue(action, target) {
  const client = containerAction;
  const listed = target && client.targets.get(target.id);
  if (document.hidden || !listed || listed.name !== target.name ||
      listed.image !== target.image || listed.state !== target.state || client.busy ||
      (action !== "status" && (!Object.hasOwn(CONTAINER_ACTION_LABELS, action) ||
       !containerActionCan(action, target)))) return;
  const serverId = client.serverId, token = state.token, base = state.base;
  const server = state.servers.find((item) => String(item.id) === String(serverId));
  const snapshot = server?.latest?.details?.containers;
  if (!containerActionReady(snapshot, server) ||
      !snapshot.engines[0].containers.some((item) => item?.id === listed.id &&
        item.name === listed.name && item.image === listed.image && item.state === listed.state)) return;
  const payload = { action, engine: "docker", id: target.id };
  const previous = client.pending;
  const key = action === "status" && previous &&
    JSON.stringify(previous.payload) === JSON.stringify(payload) ? previous.key : crypto.randomUUID();
  client.pending = action === "status" ? { key, payload } : null;
  client.busy = true;
  client.jobId = null;
  clearError($("containerActionError"));
  $("containerActionStatus").textContent = action === "status" ? "Проверяем контейнер…" : "Выполняем действие…";
  containerActionRender();
  const generation = client.generation;
  const current = () => containerActionCurrent(generation, serverId, target.id, token, base);
  try {
    const reply = await request(`/api/v1/servers/${encodeURIComponent(serverId)}/containers/actions`, {
      method: "POST", headers: { "Idempotency-Key": key }, body: JSON.stringify(payload), timeoutMs: 16000,
    });
    if (!current()) return;
    const jobId = reply?.job?.id;
    if (typeof jobId !== "string" || !CONTAINER_ACTION_JOB.test(jobId) ||
        String(reply.job.server_id) !== String(serverId))
      throw new Error("Hub не вернул номер задания. Проверьте историю до повтора.");
    client.jobId = jobId;
    const deadline = Date.now() + 85000;
    while (current() && Date.now() < deadline) {
      const result = await request(`/api/v1/jobs/${encodeURIComponent(jobId)}`, { timeoutMs: 12000 });
      if (!current()) return;
      const job = result?.job;
      if (!job || job.id !== jobId || String(job.server_id) !== String(serverId))
        throw new Error("Hub вернул другое задание.");
      if (CONTAINER_ACTION_TERMINAL.has(job.state)) {
        client.pending = null;
        containerActionClearProof();
        if (job.state === "timed_out")
          throw new Error("Исход действия неизвестен. Проверьте состояние контейнера заново.");
        if (job.state !== "succeeded")
          throw new Error("Действие не подтверждено Agent. Проверьте локальную политику.");
        if (action === "status") {
          const status = containerActionValidateControl(await request(
            `/api/v1/servers/${encodeURIComponent(serverId)}/containers/control?engine=docker&id=${encodeURIComponent(target.id)}`,
            { timeoutMs: 12000 }), target.id);
          if (!current()) return;
          if (status.source_status !== "ok") throw new Error("Состояние уже устарело. Проверьте снова.");
          client.control = status;
          client.receivedAt = Date.now();
          $("containerActionStatus").textContent = `${target.name}: ${status.state} · проверено ${timestamp(status.observed_at)}.`;
        } else {
          $("containerActionStatus").textContent = `${CONTAINER_ACTION_LABELS[action]}: задание завершено. Проверьте состояние заново.`;
        }
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }
    if (current()) throw new Error("Ожидание завершилось. Проверьте состояние до новой операции.");
  } catch (error) {
    if (current()) {
      const rejected = action !== "status" && !client.jobId &&
        [400, 401, 403, 404, 409, 503].includes(error.status);
      if (action !== "status") {
        client.pending = null;
        containerActionClearProof(rejected ? "Действие отклонено до очереди." :
          "Исход действия неизвестен. Проверьте состояние заново.");
      }
      showError($("containerActionError"), error.status === 404 ?
        "Обновите Hub и Agent для действий с контейнерами." : rejected ?
          "Hub отклонил действие до очереди. Проверьте права, список и локальную политику." :
          action !== "status" ? "Действие могло выполниться. Проверьте состояние перед новой операцией." :
            error.status === undefined && !client.jobId ?
              "Ответ потерян. Повтор проверки использует тот же ключ запроса." :
              error.message || "Не удалось проверить контейнер.");
    }
  } finally {
    if (current()) { client.busy = false; containerActionRender(); }
  }
}

function containerActionPrepare(action) {
  const target = containerActionTarget();
  if (!Object.hasOwn(CONTAINER_ACTION_LABELS, action) || !containerActionCan(action, target)) return;
  const server = state.servers.find((item) => String(item.id) === String(containerAction.serverId));
  containerAction.confirmation = { action, target, state: containerAction.control.state,
    generation: containerAction.generation, token: state.token, base: state.base, serverId: server.id };
  $("containerActionDialogTitle").textContent = `${CONTAINER_ACTION_LABELS[action]} контейнер?`;
  $("containerActionDialogSummary").textContent = `${target.name} · ${target.id.slice(0, 12)} · сейчас: ${containerAction.control.state}`;
  $("containerActionDialogServer").textContent = `Сервер: ${server.name || server.id}`;
  clearError($("containerActionDialogError"));
  $("containerActionDialog").showModal();
}

async function containerActionConfirm() {
  const pending = containerAction.confirmation;
  if (!pending) return;
  const target = containerActionTarget();
  if (pending.generation !== containerAction.generation ||
      !containerActionCurrent(pending.generation, pending.serverId, pending.target.id,
        pending.token, pending.base) ||
      !target || target.id !== pending.target.id || target.name !== pending.target.name ||
      target.image !== pending.target.image || containerAction.control?.state !== pending.state ||
      !containerActionCan(pending.action, target)) {
    showError($("containerActionDialogError"), "Состояние изменилось. Проверьте контейнер заново.");
    return;
  }
  $("containerActionConfirm").disabled = true;
  $("containerActionCancel").disabled = true;
  try {
    await containerActionQueue(pending.action, target);
    if (containerAction.confirmation === pending) $("containerActionDialog").close();
  } finally {
    if (containerAction.confirmation === pending) {
      $("containerActionConfirm").disabled = false;
      $("containerActionCancel").disabled = false;
    }
  }
}

$("containerActionForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const target = containerActionTarget();
  if (target) void containerActionQueue("status", target);
});
$("containerActionTarget").addEventListener("change", () => {
  containerAction.generation++;
  containerAction.pending = null;
  containerAction.jobId = null;
  containerAction.busy = false;
  containerActionClearProof("Проверьте состояние выбранного контейнера.");
  containerActionRender();
});
for (const action of Object.keys(CONTAINER_ACTION_LABELS)) {
  $("containerAction" + action[0].toUpperCase() + action.slice(1)).addEventListener(
    "click", () => containerActionPrepare(action));
}
$("containerActionConfirm").addEventListener("click", containerActionConfirm);
$("containerActionCancel").addEventListener("click", () => {
  if (!containerAction.busy) $("containerActionDialog").close();
});
$("containerActionDialog").addEventListener("cancel", (event) => {
  if (containerAction.busy) event.preventDefault();
});
$("containerActionDialog").addEventListener("close", () => {
  if (!containerAction.busy) containerAction.confirmation = null;
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    containerAction.generation++;
    containerAction.pending = null;
    containerActionClearProof("Вкладка скрыта. Проверьте состояние заново.");
    if ($("containerActionDialog").open) $("containerActionDialog").close();
    containerActionRender();
  }
});

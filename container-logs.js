/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// Container output may contain application secrets. Keep it only in this tab's
// DOM for at most five minutes. The Hub result is also transient and scoped to
// the requesting admin session; no log text enters localStorage or a URL.
const containerLogs = { generation: 0, serverId: null, targets: new Map(),
  pending: null, jobId: null, busy: false, outputTimer: null };
const CONTAINER_LOG_DOM_TTL_MS = 5 * 60 * 1000;
const CONTAINER_LOG_TERMINAL = new Set(["succeeded", "failed", "timed_out", "output_limited", "cancelled"]);
const CONTAINER_LOG_ID = /^[0-9a-f]{64}$/;
const CONTAINER_LOG_JOB_ID = /^[0-9a-f-]{36}$/;
const CONTAINER_LOG_MANAGED_IMAGES = new Set(["sovagrid-hub:local", "sovagrid-web:local"]);

function containerLogsClearOutput(message = "Запрос ещё не отправлен.") {
  if (containerLogs.outputTimer !== null) clearTimeout(containerLogs.outputTimer);
  containerLogs.outputTimer = null;
  $("containerLogsOutput").textContent = "";
  $("containerLogsResult").textContent = message;
  clearError($("containerLogsError"));
}

function containerLogsReset() {
  containerLogs.generation++;
  containerLogs.serverId = null;
  containerLogs.targets = new Map();
  containerLogs.pending = null;
  containerLogs.jobId = null;
  containerLogs.busy = false;
  $("containerLogsTarget").replaceChildren();
  $("containerLogsTarget").value = "";
  $("containerLogsTarget").disabled = true;
  $("containerLogsLines").disabled = true;
  containerLogsClearOutput();
  $("containerLogsHint").textContent = "Выберите работающий сервер с включённым инвентарём контейнеров.";
  $("containerLogsRead").disabled = true;
}
globalThis.containerLogsReset = containerLogsReset;

function containerLogsSelectedServer(serverId) {
  if (String(containerLogs.serverId) === String(serverId)) return;
  containerLogsReset();
  containerLogs.serverId = serverId;
}
globalThis.containerLogsSelectedServer = containerLogsSelectedServer;

function containerLogsAccessChanged() {
  const server = state.servers.find((item) => String(item.id) === String(state.selectedId));
  if (!hubCanAdmin(server)) containerLogsReset();
}
globalThis.containerLogsAccessChanged = containerLogsAccessChanged;

// The Agent's collected_at may retain its own clock skew even when Hub
// accepts the metric using receipt time. Hub checks inventory freshness from
// last_seen; the browser therefore validates structure and online status,
// then lets Hub make the authoritative time and ACL decision.
function containerLogsReady(snapshot, server) {
  if (!server || !hubCanAdmin(server) || !server.online || !server.remote_commands_enabled ||
      !snapshot || snapshot.version !== 1 || !Number.isSafeInteger(snapshot.collected_at) ||
      snapshot.collected_at < 1 || snapshot.collected_at > 253402300799 ||
      !Array.isArray(snapshot.engines) || snapshot.engines.length !== 2) return false;
  return snapshot.engines.every((source, index) => source?.engine === ["docker", "podman"][index] &&
    ["ok", "unavailable"].includes(source.source_status) &&
    typeof source.truncated === "boolean" && Array.isArray(source.containers) &&
    source.containers.length <= 12);
}

function containerLogsRender(snapshot, server) {
  containerLogsSelectedServer(server?.id ?? null);
  const admin = hubCanAdmin(server);
  $("containerLogsPanel").hidden = !admin;
  if (!admin) { containerLogsReset(); return; }
  const ready = containerLogsReady(snapshot, server);
  const targets = new Map();
  if (ready) for (const source of snapshot.engines) {
    if (source.source_status !== "ok" || source.truncated) continue;
    for (const item of source.containers) {
      if (!item || typeof item.id !== "string" || !CONTAINER_LOG_ID.test(item.id) ||
          typeof item.name !== "string" || !item.name || item.name.length > 96 ||
          !CONTAINER_LOG_MANAGED_IMAGES.has(item.image)) continue;
      const key = `${source.engine}:${item.id}`;
      targets.set(key, { engine: source.engine, id: item.id, name: item.name });
    }
  }
  const previous = $("containerLogsTarget").value;
  const selected = targets.has(previous) ? previous : targets.keys().next().value || "";
  if (!selected || (previous && previous !== selected)) {
    containerLogs.generation++;
    containerLogs.pending = null;
    containerLogs.jobId = null;
    containerLogs.busy = false;
    containerLogsClearOutput(selected ? "Выберите контейнер и запросите журнал." : "Журналы сейчас недоступны.");
  }
  const options = $("containerLogsTarget");
  options.replaceChildren();
  for (const [key, target] of targets) {
    const option = document.createElement("option");
    option.value = key;
    option.textContent = `${target.name} · ${target.engine} · ${target.id.slice(0, 12)}`;
    options.append(option);
  }
  options.value = selected;
  containerLogs.targets = targets;
  const hint = !server?.online ? "Agent не на связи." :
    !server.remote_commands_enabled ? "Сначала разрешите команды для сервера." :
      !ready ? "Нужен полный снимок контейнеров от работающего Agent." :
        !targets.size ? "Нет управляемых Hub/Web контейнеров или список усечён. Другие контейнеры пока доступны только в мониторинге." :
          "Hub проверит актуальность снимка перед запросом. Журнал может содержать секреты.";
  $("containerLogsHint").textContent = hint;
  options.disabled = !targets.size || containerLogs.busy;
  $("containerLogsLines").disabled = !targets.size || containerLogs.busy;
  $("containerLogsRead").disabled = !targets.size || containerLogs.busy || state.view !== "overview";
}
globalThis.containerLogsRender = containerLogsRender;

function containerLogsCurrent(generation, serverId, token, base) {
  return generation === containerLogs.generation && !document.hidden && state.view === "overview" &&
    String(state.selectedId) === String(serverId) && String(containerLogs.serverId) === String(serverId) &&
    state.token === token && state.base === base && Boolean(token) &&
    hubCanAdmin(state.servers.find((item) => String(item.id) === String(serverId)));
}

function containerLogsSafeOutput(value) {
  if (typeof value !== "string" || new TextEncoder().encode(value).length > 8192 ||
      /[\p{C}]/u.test(value.replace(/[\n\t]/g, ""))) {
    throw new Error("Hub вернул некорректный текст журнала.");
  }
  return value;
}

async function containerLogsRead(event) {
  event?.preventDefault?.();
  if (containerLogs.busy) return;
  const serverId = containerLogs.serverId, token = state.token, base = state.base;
  const server = state.servers.find((item) => String(item.id) === String(serverId));
  const snapshot = server?.latest?.details?.containers;
  const target = containerLogs.targets.get($("containerLogsTarget").value);
  const lines = Number($("containerLogsLines").value);
  if (!containerLogsReady(snapshot, server) || !target || ![20, 50, 100].includes(lines) ||
      !state.token || state.view !== "overview") return;
  const payload = { engine: target.engine, id: target.id, lines };
  const previous = containerLogs.pending;
  const key = previous && JSON.stringify(previous.payload) === JSON.stringify(payload)
    ? previous.key : crypto.randomUUID();
  containerLogs.pending = { key, payload };
  containerLogs.jobId = null;
  containerLogs.busy = true;
  const generation = containerLogs.generation;
  containerLogsClearOutput("Запрашиваем журнал контейнера…");
  containerLogsRender(snapshot, server);
  const current = () => containerLogsCurrent(generation, serverId, token, base);
  try {
    const reply = await request(`/api/v1/servers/${encodeURIComponent(serverId)}/containers/logs`, {
      method: "POST", headers: { "Idempotency-Key": key }, body: JSON.stringify(payload), timeoutMs: 16000,
    });
    if (!current()) return;
    const jobId = reply?.job?.id;
    if (typeof jobId !== "string" || !CONTAINER_LOG_JOB_ID.test(jobId) ||
        String(reply.job.server_id) !== String(serverId)) throw new Error("Hub не вернул номер задания.");
    containerLogs.jobId = jobId;
    const deadline = Date.now() + 80000;
    while (current() && Date.now() < deadline) {
      const result = await request(`/api/v1/jobs/${encodeURIComponent(jobId)}`, { timeoutMs: 12000 });
      if (!current()) return;
      const job = result?.job;
      if (!job || job.id !== jobId || String(job.server_id) !== String(serverId))
        throw new Error("Hub вернул результат другого задания.");
      if (CONTAINER_LOG_TERMINAL.has(job.state)) {
        containerLogs.pending = null;
        if (job.state !== "succeeded") throw new Error("Agent не смог прочитать журнал контейнера.");
        if (job.output_expired || job.transient_output !== true)
          throw new Error("Временный текст журнала уже недоступен. Запросите его заново.");
        const output = containerLogsSafeOutput(job.output);
        $("containerLogsOutput").textContent = output || "За выбранный период записей нет.";
        $("containerLogsResult").textContent = `${target.name} · ${lines} строк · текст исчезнет через 5 минут.`;
        containerLogs.outputTimer = setTimeout(() => {
          if (!current() || containerLogs.jobId !== jobId) return;
          containerLogs.outputTimer = null;
          containerLogsClearOutput("Время просмотра истекло. Запросите журнал заново.");
        }, CONTAINER_LOG_DOM_TTL_MS);
        containerLogs.outputTimer?.unref?.();
        return;
      }
      $("containerLogsResult").textContent = "Ждём Agent и ответ контейнера…";
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }
    if (current()) throw new Error("Ожидание завершилось. Проверьте сервер и запросите журнал снова.");
  } catch (error) {
    if (current()) {
      if (error.status === 401 || error.status === 403) {
        containerLogsReset();
        showError($("containerLogsError"), "Hub отклонил запрос: права, разрешение команд или актуальность списка контейнеров изменились. Текст удалён из вкладки.");
      } else {
        if (error.status !== undefined || containerLogs.jobId !== null) containerLogs.pending = null;
        $("containerLogsResult").textContent = error.status === 404 ?
          "Обновите Hub и Agent для чтения журналов контейнеров." :
          "Не удалось получить журнал контейнера.";
        showError($("containerLogsError"), error.status === undefined && containerLogs.jobId === null
          ? "Ответ потерян. Повтор использует тот же ключ запроса." :
            error.message || "Не удалось прочитать журнал.");
      }
    }
  } finally {
    if (current()) {
      containerLogs.busy = false;
      containerLogsRender(server?.latest?.details?.containers, server);
    }
  }
}

$("containerLogsForm").addEventListener("submit", (event) => { void containerLogsRead(event); });
$("containerLogsTarget").addEventListener("change", () => {
  containerLogs.generation++;
  containerLogs.pending = null;
  containerLogs.jobId = null;
  containerLogsClearOutput("Выберите число строк и запросите журнал.");
});
$("containerLogsLines").addEventListener("change", () => {
  containerLogs.generation++;
  containerLogs.pending = null;
  containerLogs.jobId = null;
  containerLogsClearOutput("Запросите журнал с новым числом строк.");
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden) containerLogsReset();
  else if (state.token && state.view === "overview") {
    const server = selectedServer();
    containerLogsRender(server?.latest?.details?.containers, server);
  }
});

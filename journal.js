/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// Journal text lives only in this tab. The Hub keeps bounded job output in its
// bounded, short-lived memory, so the panel does not put it in localStorage or a URL.
const journalClient = { generation: 0, serverId: null, unitsKey: "", pending: null,
  jobId: null, jobServerId: null, requestUnit: null, requestLines: null, last: null,
  busy: false, fetching: false, completed: false, outputTimer: null,
  auto: null, autoRequesting: false };
const JOURNAL_UNIT = /^[A-Za-z0-9_.@-]{1,96}\.service$/;
const JOURNAL_DOM_TTL_MS = 5 * 60 * 1000;
const JOURNAL_AUTO_INTERVAL_MS = 30 * 1000;
const JOURNAL_AUTO_MAX_MS = 5 * 60 * 1000;

function journalSelectedServer() {
  return state.servers.find((server) => String(server.id) === String(state.selectedId));
}

function journalAllowedUnits(server) {
  const list = server?.latest?.details?.journal_units;
  if (!server?.online || !server?.remote_commands_enabled || !Array.isArray(list)) return [];
  return list.length <= 16 ? list.filter((unit) => typeof unit === "string" && JOURNAL_UNIT.test(unit)) : [];
}

function journalReset() {
  if (journalClient.outputTimer !== null) clearTimeout(journalClient.outputTimer);
  journalClient.outputTimer = null;
  journalClient.generation++;
  journalClient.serverId = null;
  journalClient.unitsKey = "";
  journalClient.pending = null;
  journalClient.jobId = null;
  journalClient.jobServerId = null;
  journalClient.requestUnit = null;
  journalClient.requestLines = null;
  journalClient.last = null;
  journalClient.busy = false;
  journalClient.fetching = false;
  journalClient.completed = false;
  journalClient.auto = null;
  journalClient.autoRequesting = false;
  $("journalUnit").replaceChildren();
  $("journalUnit").disabled = true;
  $("journalOutput").textContent = "";
  $("journalResultStatus").textContent = "Запрос ещё не отправлен.";
  clearError($("journalError"));
  clearError($("journalConfirmError"));
  if ($("journalConfirmDialog").open) $("journalConfirmDialog").close();
  $("journalPrepare").disabled = true;
  $("journalConfirm").disabled = false;
  $("journalCancel").disabled = false;
  $("journalAutoStart").disabled = true;
  $("journalAutoStop").disabled = true;
}
globalThis.journalReset = journalReset;

function journalStopAuto(message = "") {
  if (!journalClient.auto) return;
  journalClient.auto = null;
  if (message) $("journalResultStatus").textContent = message;
  journalRender();
}

function journalAutoEligible(server, units) {
  const last = journalClient.last;
  return Boolean(server && last && journalClient.completed && !journalClient.busy &&
    !journalClient.fetching && !journalClient.autoRequesting && state.view === "journal" &&
    String(last.serverId) === String(server.id) && units.includes(last.unit) &&
    $("journalUnit").value === last.unit && Number($("journalLines").value) === last.lines);
}

function journalRender() {
  const server = journalSelectedServer();
  const id = server?.id ?? null;
  if (String(journalClient.serverId) !== String(id)) {
    journalReset();
    journalClient.serverId = id;
  }
  $("journalServerName").textContent = server ? String(server.name || server.id) : "Выберите сервер";
  const units = journalAllowedUnits(server);
  if ((journalClient.requestUnit && !units.includes(journalClient.requestUnit)) ||
      (journalClient.last && !units.includes(journalClient.last.unit))) {
    journalReset();
    journalClient.serverId = id;
  }
  const key = units.join("\0");
  if (key !== journalClient.unitsKey) {
    const old = $("journalUnit").value;
    $("journalUnit").replaceChildren();
    for (const unit of units) {
      const option = document.createElement("option");
      option.value = unit;
      option.textContent = unit;
      $("journalUnit").append(option);
    }
    $("journalUnit").value = units.includes(old) ? old : units[0] || "";
    journalClient.unitsKey = key;
  }
  const available = units.length > 0;
  if (journalClient.auto && (!available || state.view !== "journal" ||
      String(journalClient.auto.serverId) !== String(id) ||
      !units.includes(journalClient.auto.unit) ||
      $("journalUnit").value !== journalClient.auto.unit ||
      Number($("journalLines").value) !== journalClient.auto.lines)) {
    journalClient.auto = null;
  }
  $("journalStatus").textContent = !server ? "Нет сервера" : !server.online ? "Нет связи" :
    !server.remote_commands_enabled ? "Команды выключены" : available ? "Доступен" : "Не разрешён";
  $("journalStatus").className = `status-badge${available ? "" : " waiting"}`;
  $("journalAccessHint").textContent = !server ? "Добавьте сервер, чтобы просматривать его журналы." :
    !server.online ? "Agent не на связи. Журналы доступны только у работающего сервера." :
    !server.remote_commands_enabled ? "Разрешите команды в Hub для этого сервера." :
    !available ? "Включите allow_systemd_journal и укажите journal_units на Agent. По умолчанию доступ закрыт." :
    "Можно читать только службы из локального списка Agent и разрешённые отдельным сервисом чтения журналов.";
  $("journalUnit").disabled = !available || journalClient.busy;
  $("journalPrepare").disabled = !available || journalClient.busy;
  $("journalAutoStart").disabled = !journalAutoEligible(server, units) || Boolean(journalClient.auto);
  $("journalAutoStop").disabled = !journalClient.auto;
}
globalThis.journalRender = journalRender;

function journalCurrent(generation, serverId, token, base) {
  return state.view === "journal" && generation === journalClient.generation &&
    String(serverId) === String(state.selectedId) &&
    token === state.token && base === state.base && Boolean(token);
}

async function journalAutoQueue() {
  const auto = journalClient.auto;
  if (!auto || journalClient.autoRequesting || journalClient.busy || !journalClient.completed ||
      journalClient.fetching || Date.now() < auto.nextAt) return;
  if (Date.now() - auto.startedAt >= JOURNAL_AUTO_MAX_MS) {
    journalStopAuto("Пять минут автообновления истекли. Запустите его снова при необходимости.");
    return;
  }
  const server = journalSelectedServer();
  if (!server || String(server.id) !== String(auto.serverId) ||
      !journalAllowedUnits(server).includes(auto.unit) ||
      $("journalUnit").value !== auto.unit || Number($("journalLines").value) !== auto.lines ||
      state.view !== "journal" || document.hidden) {
    journalStopAuto("Автообновление остановлено: сервер, служба или доступ изменились.");
    return;
  }
  const generation = journalClient.generation, token = state.token, base = state.base;
  journalClient.autoRequesting = true;
  journalRender();
  try {
    const reply = await request(`/api/v1/servers/${encodeURIComponent(auto.serverId)}/journal`, {
      method: "POST", headers: { "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({ unit: auto.unit, lines: auto.lines }),
    });
    if (!journalCurrent(generation, auto.serverId, token, base) || journalClient.auto !== auto) return;
    const jobId = reply?.job?.id;
    if (typeof jobId !== "string" || !/^[0-9a-f-]{36}$/.test(jobId)) throw new Error("Hub не вернул номер задания.");
    journalClient.jobId = jobId;
    journalClient.jobServerId = auto.serverId;
    journalClient.requestUnit = auto.unit;
    journalClient.requestLines = auto.lines;
    journalClient.completed = false;
    $("journalResultStatus").textContent = "Автообновление: ждём Agent…";
    clearError($("journalError"));
  } catch (error) {
    if (journalCurrent(generation, auto.serverId, token, base) && journalClient.auto === auto) {
      if (error.status === 401 || error.status === 403) {
        journalReset();
        journalRender();
        showError($("journalError"), "Доступ к журналу изменился. Текст удалён из вкладки.");
      } else {
        journalStopAuto("Автообновление остановлено. Последний ответ сохранён только в этой вкладке.");
        showError($("journalError"), error.status ? error.message :
          "Ответ не получен; запрос мог попасть в очередь. Автообновление остановлено без повтора.");
      }
    }
  } finally {
    if (generation === journalClient.generation) {
      journalClient.autoRequesting = false;
      journalRender();
    }
  }
}

async function journalRefresh() {
  journalRender();
  if (journalClient.auto && Date.now() - journalClient.auto.startedAt >= JOURNAL_AUTO_MAX_MS) {
    journalStopAuto("Пять минут автообновления истекли. Запустите его снова при необходимости.");
  }
  if (!journalClient.jobId || journalClient.completed || journalClient.fetching) {
    await journalAutoQueue();
    return;
  }
  const generation = journalClient.generation, serverId = journalClient.jobServerId;
  const token = state.token, base = state.base, jobId = journalClient.jobId;
  if (!journalCurrent(generation, serverId, token, base)) return;
  journalClient.fetching = true;
  try {
    const reply = await request(`/api/v1/jobs/${encodeURIComponent(jobId)}`);
    if (!journalCurrent(generation, serverId, token, base) || journalClient.jobId !== jobId) return;
    const job = reply?.job;
    if (!job || String(job.server_id) !== String(serverId)) throw new Error("Hub вернул результат другого сервера.");
    const stateLabel = { queued: "Ждём Agent…", delivered: "Agent читает журнал…",
      succeeded: "Журнал загружен.", failed: "Не удалось прочитать журнал.",
      timed_out: "Время чтения истекло.", output_limited: "Вывод ограничен 8 КБ." };
    $("journalResultStatus").textContent = stateLabel[job.state] || "Ожидаем результат…";
    if (["succeeded", "failed", "timed_out", "output_limited", "cancelled"].includes(job.state)) {
      journalClient.completed = true;
      if (journalClient.outputTimer !== null) clearTimeout(journalClient.outputTimer);
      journalClient.outputTimer = null;
      const output = typeof job.output === "string" ? job.output.slice(0, 8192) : "";
      $("journalOutput").textContent = job.output_expired === true
        ? "Текст журнала больше недоступен. Запросите его заново."
        : output || (job.state === "succeeded" ? "За последние 24 часа записей нет." : "Журнал недоступен.");
      if (job.output_expired === true) $("journalResultStatus").textContent = "Время просмотра истекло.";
      if (job.state === "cancelled") $("journalResultStatus").textContent = "Запрос отменён.";
      journalClient.last = job.state === "succeeded" && job.output_expired !== true &&
        journalClient.requestUnit && Number.isInteger(journalClient.requestLines)
        ? { serverId, unit: journalClient.requestUnit, lines: journalClient.requestLines } : null;
      if (journalClient.auto) {
        if (job.state !== "succeeded" || job.output_expired === true) {
          journalStopAuto("Автообновление остановлено: чтение журнала завершилось ошибкой.");
        } else {
          journalClient.auto.nextAt = Date.now() + JOURNAL_AUTO_INTERVAL_MS;
        }
      }
      if (output && job.output_expired !== true) {
        journalClient.outputTimer = setTimeout(() => {
          if (generation !== journalClient.generation || journalClient.jobId !== jobId) return;
          journalClient.outputTimer = null;
          journalClient.last = null;
          journalStopAuto();
          $("journalOutput").textContent = "Текст журнала больше недоступен. Запросите его заново.";
          $("journalResultStatus").textContent = "Время просмотра истекло.";
          journalRender();
        }, JOURNAL_DOM_TTL_MS);
        journalClient.outputTimer?.unref?.();
      }
    }
  } catch (error) {
    if (journalCurrent(generation, serverId, token, base)) {
      if (error.status === 401 || error.status === 403) {
        journalReset();
        journalRender();
        showError($("journalError"), "Доступ к журналу изменился. Текст удалён из вкладки.");
      } else {
        showError($("journalError"), error.message || "Не удалось получить журнал.");
      }
    }
  } finally {
    if (generation === journalClient.generation) {
      journalClient.fetching = false;
      journalRender();
    }
  }
}
globalThis.journalRefresh = journalRefresh;

function journalPrepare() {
  journalStopAuto();
  clearError($("journalError"));
  const server = journalSelectedServer();
  const unit = $("journalUnit").value;
  const lines = Number($("journalLines").value);
  if (!server || !journalAllowedUnits(server).includes(unit) || ![20, 50, 100].includes(lines)) {
    showError($("journalError"), "Выберите доступную службу и число строк.");
    return;
  }
  journalClient.pending = { serverId: server.id, unit, lines, key: crypto.randomUUID() };
  $("journalConfirmSummary").textContent = `${String(server.name || server.id)} · ${unit} · последние ${lines} строк`;
  clearError($("journalConfirmError"));
  $("journalConfirmDialog").showModal();
}

async function journalConfirm() {
  const pending = journalClient.pending;
  if (!pending || journalClient.busy) return;
  const server = journalSelectedServer();
  if (!server || String(server.id) !== String(pending.serverId) ||
      !journalAllowedUnits(server).includes(pending.unit)) {
    showError($("journalConfirmError"), "Сервер или разрешение изменились. Закройте окно и выберите службу заново.");
    return;
  }
  const generation = journalClient.generation, token = state.token, base = state.base;
  journalClient.busy = true;
  $("journalConfirm").disabled = true;
  $("journalCancel").disabled = true;
  try {
    const reply = await request(`/api/v1/servers/${encodeURIComponent(pending.serverId)}/journal`, {
      method: "POST", headers: { "Idempotency-Key": pending.key },
      body: JSON.stringify({ unit: pending.unit, lines: pending.lines }),
    });
    if (!journalCurrent(generation, pending.serverId, token, base)) return;
    const jobId = reply?.job?.id;
    if (typeof jobId !== "string" || !/^[0-9a-f-]{36}$/.test(jobId)) throw new Error("Hub не вернул номер задания.");
    journalClient.jobId = jobId;
    if (journalClient.outputTimer !== null) clearTimeout(journalClient.outputTimer);
    journalClient.outputTimer = null;
    journalClient.jobServerId = pending.serverId;
    journalClient.requestUnit = pending.unit;
    journalClient.requestLines = pending.lines;
    journalClient.last = null;
    journalClient.completed = false;
    journalClient.pending = null;
    $("journalOutput").textContent = "";
    $("journalResultStatus").textContent = "Запрос поставлен в очередь. Ждём Agent…";
    clearError($("journalError"));
    $("journalConfirmDialog").close();
    await journalRefresh();
  } catch (error) {
    if (journalCurrent(generation, pending.serverId, token, base)) {
      const message = error.status ? error.message :
        "Ответ не получен. Запрос мог попасть в очередь. Повтор использует тот же ключ и не создаст второе задание.";
      showError($("journalConfirmError"), message);
    }
  } finally {
    if (generation === journalClient.generation) {
      journalClient.busy = false;
      $("journalConfirm").disabled = false;
      $("journalCancel").disabled = false;
      journalRender();
    }
  }
}

function journalStartAuto() {
  journalRender();
  const server = journalSelectedServer();
  const units = journalAllowedUnits(server);
  if (!journalAutoEligible(server, units) || journalClient.auto) return;
  journalClient.auto = { serverId: server.id, unit: journalClient.last.unit,
    lines: journalClient.last.lines, startedAt: Date.now(),
    nextAt: Date.now() + JOURNAL_AUTO_INTERVAL_MS };
  $("journalResultStatus").textContent = "Автообновление последних строк включено на пять минут: новый снимок не чаще 30 секунд.";
  journalRender();
}

function journalUnitChanged() {
  const unit = $("journalUnit").value;
  const lines = $("journalLines").value;
  journalReset();
  journalRender();
  if (journalAllowedUnits(journalSelectedServer()).includes(unit)) $("journalUnit").value = unit;
  $("journalLines").value = lines;
  journalRender();
}

$("journalPrepare").addEventListener("click", journalPrepare);
$("journalAutoStart").addEventListener("click", journalStartAuto);
$("journalAutoStop").addEventListener("click", () => journalStopAuto("Автообновление остановлено."));
$("journalUnit").addEventListener("change", journalUnitChanged);
$("journalLines").addEventListener("change", journalUnitChanged);
$("journalConfirm").addEventListener("click", journalConfirm);
$("journalCancel").addEventListener("click", () => { if (!journalClient.busy) $("journalConfirmDialog").close(); });
$("journalConfirmDialog").addEventListener("cancel", (event) => { if (journalClient.busy) event.preventDefault(); });
$("journalConfirmDialog").addEventListener("close", () => { if (!journalClient.busy) journalClient.pending = null; });

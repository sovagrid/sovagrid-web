/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// Process pages exist only in this tab. Hub holds their text briefly in
// memory; neither this panel nor the service worker persists it.
const processInventory = { generation: 0, serverId: null, busy: false, pending: null,
  filter: "", rows: [], nextAfterPid: 0, hasMore: false, observedAt: null, jobId: null };
const PROCESS_TERMINAL_STATES = new Set(["succeeded", "failed", "timed_out", "output_limited", "cancelled"]);

function processInventoryCurrent(generation, serverId, token, base) {
  return processInventory.generation === generation && state.token === token && state.base === base &&
    Boolean(token) && String(processInventory.serverId) === String(serverId) &&
    String(state.selectedId) === String(serverId);
}

function processInventoryReset() {
  processInventory.generation++;
  Object.assign(processInventory, { serverId: null, busy: false, pending: null, filter: "",
    rows: [], nextAfterPid: 0, hasMore: false, observedAt: null, jobId: null });
  $("processInventoryFilter").value = "";
  clearError($("processInventoryError"));
  $("processInventoryStatus").textContent = "Запрос ещё не отправлен.";
  processInventoryRender();
}
globalThis.processInventoryReset = processInventoryReset;

function processInventorySelectedServer(serverId) {
  if (String(processInventory.serverId) === String(serverId)) {
    processInventoryRender(); return;
  }
  processInventoryReset();
  processInventory.serverId = serverId;
  processInventoryRender();
}
globalThis.processInventorySelectedServer = processInventorySelectedServer;

function processInventoryRender() {
  const server = state.servers.find((item) => String(item.id) === String(processInventory.serverId));
  const ready = hubCanAdmin() && server?.online && server.remote_commands_enabled;
  $("processInventoryStart").disabled = !ready || processInventory.busy;
  $("processInventoryFilter").disabled = processInventory.busy;
  $("processInventoryMore").hidden = !processInventory.hasMore;
  $("processInventoryMore").disabled = !ready || processInventory.busy || processInventory.rows.length >= 4096;
  const table = $("processInventoryTable"), body = $("processInventoryRows");
  table.hidden = !processInventory.rows.length;
  body.replaceChildren();
  for (const item of processInventory.rows) {
    const row = document.createElement("tr");
    for (const value of [String(item.pid), item.name, bytes(item.rss_bytes)]) {
      const cell = document.createElement("td"); cell.textContent = value; row.append(cell);
    }
    body.append(row);
  }
}

function processInventoryPage(output, requested) {
  let value;
  try { value = JSON.parse(output); } catch { throw new Error("Hub вернул неверный список процессов."); }
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      !Number.isSafeInteger(value.observed_at) || value.observed_at < 1 ||
      value.after_pid !== requested.after_pid || value.filter !== requested.filter ||
      !Number.isSafeInteger(value.next_after_pid) || value.next_after_pid < requested.after_pid ||
      value.next_after_pid > 2147483647 || typeof value.has_more !== "boolean" ||
      (value.has_more && value.next_after_pid === requested.after_pid) ||
      !Array.isArray(value.processes) || value.processes.length > requested.limit) {
    throw new Error("Hub вернул неверный список процессов.");
  }
  let previous = requested.after_pid;
  for (const row of value.processes) {
    if (!row || typeof row !== "object" || Array.isArray(row) ||
        !Number.isSafeInteger(row.pid) || row.pid <= previous || row.pid > value.next_after_pid ||
        typeof row.name !== "string" || !row.name || [...row.name].length > 16 ||
        /[\p{C}]/u.test(row.name) ||
        !Number.isSafeInteger(row.rss_bytes) || row.rss_bytes < 0) {
      throw new Error("Hub вернул неверный список процессов.");
    }
    previous = row.pid;
  }
  return value;
}

async function processInventoryRequest(afterPid, filter) {
  const client = processInventory;
  const serverId = client.serverId, token = state.token, base = state.base;
  if (!serverId || !token || !hubCanAdmin() || client.busy) return;
  const server = state.servers.find((item) => String(item.id) === String(serverId));
  if (!server?.online || !server.remote_commands_enabled) return;
  const generation = client.generation;
  const payload = { after_pid: afterPid, limit: 32, filter };
  const existing = client.pending;
  const key = existing && JSON.stringify(existing.payload) === JSON.stringify(payload) ? existing.key : crypto.randomUUID();
  client.pending = { key, payload };
  client.jobId = null;
  client.busy = true;
  clearError($("processInventoryError"));
  $("processInventoryStatus").textContent = "Запрашиваем страницу процессов…";
  processInventoryRender();
  const current = () => processInventoryCurrent(generation, serverId, token, base);
  try {
    const result = await request(`/api/v1/servers/${encodeURIComponent(serverId)}/processes/snapshot`, {
      method: "POST", headers: { "Idempotency-Key": key }, body: JSON.stringify(payload), timeoutMs: 16000,
    });
    if (!current()) return;
    if (!result?.job?.id || String(result.job.server_id) !== String(serverId))
      throw new Error("Hub не вернул задание. Проверьте сервер перед повтором.");
    client.jobId = result.job.id;
    const deadline = Date.now() + 80000;
    while (current() && Date.now() < deadline) {
      const reply = await request(`/api/v1/jobs/${encodeURIComponent(client.jobId)}`, { timeoutMs: 12000 });
      if (!current()) return;
      const job = reply?.job;
      if (!job || job.id !== client.jobId || String(job.server_id) !== String(serverId))
        throw new Error("Hub вернул другое задание.");
      if (PROCESS_TERMINAL_STATES.has(job.state)) {
        client.pending = null;
        if (job.state !== "succeeded") throw new Error("Не удалось получить список процессов. Проверьте доступ Agent.");
        if (job.output_expired || !job.transient_output || !job.output)
          throw new Error("Временный результат истёк. Запросите список заново.");
        const page = processInventoryPage(job.output, payload);
        if (afterPid === 0) client.rows = [];
        client.rows.push(...page.processes);
        client.nextAfterPid = page.next_after_pid;
        client.hasMore = page.has_more && client.rows.length < 4096;
        client.observedAt = page.observed_at;
        $("processInventoryStatus").textContent = `${client.rows.length} процессов · страница на ${timestamp(page.observed_at)}${client.hasMore ? " · есть следующая" : page.has_more ? " · достигнут предел панели, уточните фильтр" : ""}.`;
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }
    if (current()) throw new Error("Ожидание завершилось. Новую страницу можно запросить снова.");
  } catch (error) {
    if (current()) {
      if (error.status === undefined && client.jobId === null) {
        $("processInventoryStatus").textContent = "Ответ потерян; повтор использует тот же ключ запроса.";
      } else if (error.status === 404) {
        client.pending = null;
        $("processInventoryStatus").textContent = "Обновите Hub и Agent для подробного списка процессов.";
      }
      showError($("processInventoryError"), error.message || "Не удалось получить процессы.");
    }
  } finally {
    if (current()) { client.busy = false; processInventoryRender(); }
  }
}

$("processInventoryForm").addEventListener("submit", (event) => {
  event.preventDefault();
  if (processInventory.busy) return;
  const filter = $("processInventoryFilter").value.trim();
  if ([...filter].length > 16 || /[\p{C}\p{Zl}\p{Zp}]/u.test(filter)) {
    showError($("processInventoryError"), "Фильтр должен содержать до 16 печатных символов."); return;
  }
  processInventory.filter = filter;
  processInventory.rows = [];
  processInventory.hasMore = false;
  processInventory.jobId = null;
  processInventoryRender();
  void processInventoryRequest(0, filter);
});
$("processInventoryMore").addEventListener("click", () => {
  if (processInventory.hasMore && !processInventory.busy)
    void processInventoryRequest(processInventory.nextAfterPid, processInventory.filter);
});

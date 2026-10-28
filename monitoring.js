/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

const monitoringClient = { generation: 0, refreshSeq: 0, data: null, dirty: false,
  conflict: false, busy: false, loading: false };
const MONITORING_FIELDS = { high_cpu: "monitoringCpu", high_memory: "monitoringMemory",
  high_disk: "monitoringDisk", offline_seconds: "monitoringOffline", trigger_minutes: "monitoringTrigger" };

function monitoringCurrent(generation, token, base) {
  return monitoringClient.generation === generation && state.token === token &&
    state.base === base && Boolean(token);
}

function monitoringValidate(payload) {
  const data = payload?.settings;
  const legacy = data && !Object.prototype.hasOwnProperty.call(data, "trigger_minutes");
  if (!data || typeof data !== "object" || !Number.isSafeInteger(data.revision) || data.revision < 0 ||
      !Number.isSafeInteger(data.offline_seconds) || data.offline_seconds < 1 || data.offline_seconds > 86400 ||
      (!legacy && (!Number.isSafeInteger(data.trigger_minutes) || data.trigger_minutes < 0 || data.trigger_minutes > 1440)) ||
      [data.high_cpu, data.high_memory, data.high_disk].some((value) =>
        typeof value !== "number" || !Number.isFinite(value) || value < 1 || value > 100)) {
    throw new Error("Центр мониторинга вернул неверные правила оповещений.");
  }
  return { ...data, trigger_minutes: legacy ? 0 : data.trigger_minutes, legacy: Boolean(legacy) };
}

function monitoringRender() {
  const client = monitoringClient;
  const readOnly = globalThis.hubCanGlobalAdmin?.() === false;
  if (client.data && !client.dirty) {
    for (const [key, id] of Object.entries(MONITORING_FIELDS)) $(id).value = String(client.data[key]);
  }
  for (const id of Object.values(MONITORING_FIELDS)) $(id).disabled = readOnly || !client.data || client.busy;
  $("monitoringTrigger").disabled = readOnly || !client.data || client.busy || client.data.legacy;
  $("monitoringTriggerHint").textContent = client.data?.legacy
    ? "Обновите центр мониторинга Hub, чтобы настроить задержку тревоги. Остальные правила доступны."
    : "0 минут — тревога сразу. При большем значении Hub ждёт устойчивого превышения порога или отсутствия связи. Тревога CPU, памяти, диска и служб подтверждается новым измерением; отсутствие связи проверяется каждые 10 секунд.";
  $("monitoringSave").disabled = readOnly || !client.data || !client.dirty || client.conflict || client.busy;
  $("monitoringSave").hidden = readOnly;
  $("monitoringSave").textContent = client.busy ? "Сохраняем…" : "Сохранить правила";
  $("monitoringReload").disabled = !client.data || client.busy || client.loading;
  if (client.conflict) {
    showError($("monitoringError"),
      "Правила изменились в другой вкладке. Нажмите «Вернуть сохранённое», проверьте значения и повторите изменение.");
  }
}

function monitoringReset() {
  monitoringClient.generation++;
  monitoringClient.refreshSeq++;
  Object.assign(monitoringClient, { data: null, dirty: false, conflict: false,
    busy: false, loading: false });
  for (const id of Object.values(MONITORING_FIELDS)) $(id).value = "";
  clearError($("monitoringError"));
  $("monitoringMessage").hidden = true;
  $("monitoringMessage").textContent = "";
  monitoringRender();
}
globalThis.monitoringReset = monitoringReset;

async function monitoringRefresh({ replace = false } = {}) {
  if (!state.token || monitoringClient.busy) return;
  const generation = monitoringClient.generation, token = state.token, base = state.base;
  const seq = ++monitoringClient.refreshSeq;
  monitoringClient.loading = true;
  monitoringRender();
  try {
    const data = monitoringValidate(await request("/api/v1/monitoring/settings"));
    if (!monitoringCurrent(generation, token, base) || seq !== monitoringClient.refreshSeq) return;
    if (!replace && monitoringClient.dirty && monitoringClient.data &&
        monitoringClient.data.revision !== data.revision) monitoringClient.conflict = true;
    monitoringClient.data = data;
    if (replace) {
      monitoringClient.dirty = false;
      monitoringClient.conflict = false;
      clearError($("monitoringError"));
      $("monitoringMessage").hidden = true;
    }
  } catch (error) {
    if (monitoringCurrent(generation, token, base) && seq === monitoringClient.refreshSeq) {
      showError($("monitoringError"), error.message || "Не удалось загрузить правила оповещений.");
    }
  } finally {
    if (monitoringCurrent(generation, token, base) && seq === monitoringClient.refreshSeq) {
      monitoringClient.loading = false;
      monitoringRender();
    }
  }
}
globalThis.monitoringRefresh = monitoringRefresh;

function monitoringValues() {
  const result = {};
  for (const [key, id] of Object.entries(MONITORING_FIELDS)) {
    const raw = $(id).value.trim();
    const number = Number(raw.replace(",", "."));
    const invalid = key === "offline_seconds" ? !Number.isSafeInteger(number) || number < 10 || number > 86400 :
      key === "trigger_minutes" ? !Number.isSafeInteger(number) || number < 0 || number > 1440 :
        number < 1 || number > 100;
    if (!/^\d+(?:[.,]\d+)?$/.test(raw) || !Number.isFinite(number) || invalid) {
      throw new Error(key === "offline_seconds" ? "Время без связи: целое число секунд от 10 до 86400." :
        key === "trigger_minutes" ? "Задержка тревоги: целое число минут от 0 до 1440." :
          "Пороги нагрузки, памяти и диска: числа от 1 до 100%.");
    }
    result[key] = number;
  }
  return result;
}

async function monitoringSave(event) {
  event.preventDefault();
  if (globalThis.hubCanGlobalAdmin?.() === false) return;
  if (!state.token || !monitoringClient.data || monitoringClient.busy || !monitoringClient.dirty) return;
  if (monitoringClient.conflict) { monitoringRender(); return; }
  clearError($("monitoringError"));
  $("monitoringMessage").hidden = true;
  let values;
  try { values = monitoringValues(); }
  catch (error) { showError($("monitoringError"), error.message); return; }
  const generation = monitoringClient.generation, token = state.token, base = state.base;
  const previousRevision = monitoringClient.data.revision;
  const seq = ++monitoringClient.refreshSeq;
  monitoringClient.busy = true;
  monitoringRender();
  try {
    if (monitoringClient.data.legacy) delete values.trigger_minutes;
    const payload = await request("/api/v1/monitoring/settings", { method: "POST",
      body: JSON.stringify({ ...values, revision: previousRevision }) });
    if (!monitoringCurrent(generation, token, base) || seq !== monitoringClient.refreshSeq) return;
    const data = monitoringValidate(payload);
    if (data.revision !== previousRevision + 1) throw new Error("Центр мониторинга вернул неполный ответ.");
    monitoringClient.data = data;
    monitoringClient.dirty = false;
    monitoringClient.conflict = false;
    $("monitoringMessage").textContent = "Сохранено. Новые правила действуют без перезапуска.";
    $("monitoringMessage").hidden = false;
  } catch (error) {
    if (!monitoringCurrent(generation, token, base) || seq !== monitoringClient.refreshSeq) return;
    if (error.status === 409) monitoringClient.conflict = true;
    else showError($("monitoringError"), error.message || "Не удалось сохранить правила.");
  } finally {
    if (monitoringCurrent(generation, token, base) && seq === monitoringClient.refreshSeq) {
      monitoringClient.busy = false;
      monitoringRender();
    }
  }
}

$("monitoringForm").addEventListener("submit", monitoringSave);
$("monitoringReload").addEventListener("click", () => monitoringRefresh({ replace: true }));
for (const id of Object.values(MONITORING_FIELDS)) $(id).addEventListener("input", () => {
  if (!monitoringClient.data || monitoringClient.busy) return;
  monitoringClient.dirty = true;
  $("monitoringMessage").hidden = true;
  if (!monitoringClient.conflict) clearError($("monitoringError"));
  monitoringRender();
});
monitoringRender();

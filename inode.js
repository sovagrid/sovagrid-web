/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

const inodeClient = { generation: 0, seq: 0, data: null, dirty: false,
  conflict: false, busy: false, loading: false, unsupported: false };

function inodeCurrent(generation, token, base) {
  return inodeClient.generation === generation && state.token === token && state.base === base && Boolean(token);
}

function inodeValidate(payload) {
  const data = payload?.settings;
  if (!data || typeof data !== "object" ||
      !Number.isSafeInteger(data.revision) || data.revision < 0 ||
      !Number.isSafeInteger(data.hold_seconds) || data.hold_seconds < 30 || data.hold_seconds > 86400 ||
      !(data.threshold_percent === null || typeof data.threshold_percent === "number" &&
        Number.isFinite(data.threshold_percent) && data.threshold_percent > 0 && data.threshold_percent <= 100))
    throw new Error("Центр мониторинга вернул неверное правило inode.");
  return data;
}

function inodeRender() {
  const client = inodeClient, readOnly = !hubCanGlobalAdmin();
  if (client.data && !client.dirty) {
    $("inodeEnabled").checked = client.data.threshold_percent !== null;
    $("inodeThreshold").value = String(client.data.threshold_percent ?? 90);
    $("inodeHold").value = String(client.data.hold_seconds);
  }
  const enabled = $("inodeEnabled").checked;
  $("inodeFields").hidden = !enabled;
  $("inodeStatus").textContent = client.data
    ? client.data.threshold_percent === null ? "Правило выключено. Показатели inode остаются видны в обзоре сервера."
      : `Правило включено: порог ${client.data.threshold_percent}%, задержка ${client.data.hold_seconds} сек.`
    : client.unsupported ? "Этот Hub пока не поддерживает правило inode. Обновите Hub."
      : client.loading ? "Загружаем правило…" : "Состояние правила неизвестно. Обновите данные.";
  $("inodeEnabled").disabled = readOnly || !client.data || client.busy;
  $("inodeThreshold").disabled = readOnly || !client.data || client.busy || !enabled;
  $("inodeHold").disabled = readOnly || !client.data || client.busy || !enabled;
  $("inodeThreshold").required = enabled;
  $("inodeHold").required = enabled;
  $("inodeSave").hidden = readOnly;
  $("inodeSave").disabled = readOnly || !client.data || !client.dirty || client.conflict || client.busy;
  $("inodeSave").textContent = client.busy ? "Сохраняем…" : "Сохранить правило";
  $("inodeReload").disabled = !state.token || client.busy || client.loading;
  if (client.conflict) showError($("inodeError"),
    "Правило могло измениться или сохраниться в другой вкладке. Нажмите «Вернуть сохранённое», проверьте значения и повторите изменение.");
}

function inodeReset() {
  inodeClient.generation++; inodeClient.seq++;
  Object.assign(inodeClient, { data: null, dirty: false, conflict: false,
    busy: false, loading: false, unsupported: false });
  $("inodeEnabled").checked = false; $("inodeThreshold").value = "90"; $("inodeHold").value = "60";
  clearError($("inodeError")); $("inodeMessage").hidden = true; $("inodeMessage").textContent = "";
  inodeRender();
}
globalThis.inodeReset = inodeReset;

async function inodeRefresh({ replace = false } = {}) {
  if (!state.token || inodeClient.busy) return;
  const generation = inodeClient.generation, token = state.token, base = state.base, seq = ++inodeClient.seq;
  inodeClient.loading = true; inodeRender();
  try {
    const data = inodeValidate(await request("/api/v1/monitoring/inode-settings"));
    if (!inodeCurrent(generation, token, base) || seq !== inodeClient.seq) return;
    if (!replace && inodeClient.dirty && inodeClient.data && inodeClient.data.revision !== data.revision)
      inodeClient.conflict = true;
    inodeClient.data = data; inodeClient.unsupported = false;
    if (replace) {
      inodeClient.dirty = false; inodeClient.conflict = false;
      clearError($("inodeError")); $("inodeMessage").hidden = true;
    }
  } catch (error) {
    if (!inodeCurrent(generation, token, base) || seq !== inodeClient.seq) return;
    if (error.status === 404) { inodeClient.data = null; inodeClient.unsupported = true; }
    showError($("inodeError"), error.status === 404
      ? "Обновите Hub, чтобы настроить оповещение о свободных inode."
      : error.message || "Не удалось загрузить правило inode.");
  } finally {
    if (inodeCurrent(generation, token, base) && seq === inodeClient.seq) {
      inodeClient.loading = false; inodeRender();
    }
  }
}
globalThis.inodeRefresh = inodeRefresh;

function inodeValues() {
  const holdRaw = $("inodeHold").value;
  if (!$("inodeEnabled").checked) return { threshold_percent: null, hold_seconds: inodeClient.data.hold_seconds };
  const thresholdRaw = $("inodeThreshold").value.trim();
  const threshold = Number(thresholdRaw.replace(",", ".")), hold = Number(holdRaw);
  if (!/^\d+(?:[.,]\d+)?$/.test(thresholdRaw) || !Number.isFinite(threshold) || threshold <= 0 || threshold > 100)
    throw new Error("Порог inode должен быть больше 0 и не выше 100%.");
  if (!/^\d+$/.test(holdRaw) || !Number.isSafeInteger(hold) || hold < 30 || hold > 86400)
    throw new Error("Задержка тревоги inode: целое число секунд от 30 до 86400.");
  return { threshold_percent: threshold, hold_seconds: hold };
}

async function inodeSave(event) {
  event.preventDefault();
  if (!hubCanGlobalAdmin() || !state.token || !inodeClient.data || inodeClient.busy ||
      !inodeClient.dirty || inodeClient.conflict) return;
  clearError($("inodeError")); $("inodeMessage").hidden = true;
  let values;
  try { values = inodeValues(); } catch (error) { showError($("inodeError"), error.message); return; }
  const generation = inodeClient.generation, token = state.token, base = state.base;
  const revision = inodeClient.data.revision, seq = ++inodeClient.seq;
  inodeClient.busy = true; inodeRender();
  try {
    const payload = await request("/api/v1/monitoring/inode-settings", { method: "POST",
      body: JSON.stringify({ ...values, revision }) });
    if (!inodeCurrent(generation, token, base) || seq !== inodeClient.seq) return;
    const saved = inodeValidate(payload);
    if (saved.revision !== revision + 1) throw new Error("Hub не подтвердил новую ревизию правила inode.");
    inodeClient.data = saved; inodeClient.dirty = false; inodeClient.conflict = false;
    $("inodeMessage").textContent = "Правило сохранено. Оно действует без перезапуска Hub.";
    $("inodeMessage").hidden = false;
  } catch (error) {
    if (!inodeCurrent(generation, token, base) || seq !== inodeClient.seq) return;
    // A lost POST response may mean that the change applied. Require a fresh
    // read before another mutation rather than replaying an uncertain write.
    inodeClient.conflict = true;
    showError($("inodeError"), error.status === 409
      ? "Правило изменилось в другой вкладке. Верните сохранённое перед новой попыткой."
      : "Не удалось подтвердить сохранение. Верните сохранённое перед новой попыткой.");
  } finally {
    if (inodeCurrent(generation, token, base) && seq === inodeClient.seq) {
      inodeClient.busy = false; inodeRender();
    }
  }
}

$("inodeForm").addEventListener("submit", inodeSave);
$("inodeReload").addEventListener("click", () => inodeRefresh({ replace: true }));
for (const id of ["inodeEnabled", "inodeThreshold", "inodeHold"]) $(id).addEventListener("change", () => {
  if (!hubCanGlobalAdmin() || !inodeClient.data || inodeClient.busy) return;
  inodeClient.dirty = true; $("inodeMessage").hidden = true;
  if (!inodeClient.conflict) clearError($("inodeError"));
  inodeRender();
});
for (const id of ["inodeThreshold", "inodeHold"]) $(id).addEventListener("input", () => {
  if (!hubCanGlobalAdmin() || !inodeClient.data || inodeClient.busy) return;
  inodeClient.dirty = true; $("inodeMessage").hidden = true;
  if (!inodeClient.conflict) clearError($("inodeError"));
  inodeRender();
});
inodeRender();

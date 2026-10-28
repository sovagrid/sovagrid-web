/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

const serviceControl = { generation: 0, serverId: null, unit: "", control: null,
  receivedAt: 0, busy: false, pending: null, confirmation: null, jobId: null };
const SERVICE_UNIT = /^[A-Za-z0-9][A-Za-z0-9_.@-]{0,87}\.service$/;
const SERVICE_TERMINAL = new Set(["succeeded", "failed", "timed_out", "output_limited", "cancelled"]);
const SERVICE_ACTIONS = { start: "Запустить", stop: "Остановить", restart: "Перезапустить" };
// Match the Hub and Agent's reserved access/control-plane units for immediate
// feedback. Their independent checks remain authoritative, including aliases.
const SERVICE_PROTECTED_BASES = new Set([
  "ssh", "sshd", "dropbear", "dbus", "networking", "networkmanager",
  "network-manager", "docker", "containerd", "podman", "cri-o",
  "nftables", "ufw", "firewalld", "iptables", "netfilter-persistent",
  "caddy", "wg-quick", "awg-quick", "openvpn", "strongswan", "ipsec",
]);

function serviceControlValidUnit(unit) {
  return SERVICE_UNIT.test(unit) && !unit.endsWith("@.service");
}

function serviceControlProtectedUnit(unit) {
  if (!serviceControlValidUnit(unit)) return false;
  const stem = unit.slice(0, -".service".length).toLowerCase();
  const base = stem.split("@", 1)[0];
  return SERVICE_PROTECTED_BASES.has(base) ||
    ["sovagrid", "systemd-", "amnezia", "autossh"].some((prefix) => base.startsWith(prefix)) ||
    base.includes("tunnel");
}

function serviceControlCurrent(generation, serverId, token, base) {
  return serviceControl.generation === generation && state.token === token && state.base === base &&
    Boolean(token) && String(serviceControl.serverId) === String(serverId) &&
    String(state.selectedId) === String(serverId);
}

function serviceControlReset() {
  serviceControl.generation++;
  Object.assign(serviceControl, { serverId: null, unit: "", control: null, receivedAt: 0,
    busy: false, pending: null, confirmation: null, jobId: null });
  if ($("serviceControlDialog").open) $("serviceControlDialog").close();
  $("serviceControlUnit").value = "";
  $("serviceControlStatus").textContent = "Служба ещё не проверена.";
  clearError($("serviceControlError"));
  clearError($("serviceControlDialogError"));
  serviceControlRender();
}
globalThis.serviceControlReset = serviceControlReset;

function serviceControlSelectedServer(serverId) {
  if (String(serviceControl.serverId) !== String(serverId)) {
    serviceControlReset();
    serviceControl.serverId = serverId;
  }
  const server = state.servers.find((item) => String(item.id) === String(serverId));
  const suggestions = $("serviceControlSuggestions"); suggestions.replaceChildren();
  const names = server?.latest?.details?.services?.units;
  if (Array.isArray(names)) {
    for (const unit of [...new Set(names.map((item) => item?.name).filter(serviceControlValidUnit))].slice(0, 16)) {
      const option = document.createElement("option"); option.value = unit; suggestions.append(option);
    }
  }
  serviceControlRender();
}
globalThis.serviceControlSelectedServer = serviceControlSelectedServer;

function serviceControlRender() {
  const client = serviceControl;
  const server = state.servers.find((item) => String(item.id) === String(client.serverId));
  const ready = hubCanAdmin() && server?.online && server.remote_commands_enabled;
  const selectedUnit = $("serviceControlUnit").value.trim();
  const protectedUnit = serviceControlProtectedUnit(selectedUnit);
  const checked = client.control?.source_status === "ok" &&
    client.control.unit === client.unit && selectedUnit === client.unit &&
    Date.now() - client.receivedAt < 85000;
  $("serviceControlCheck").disabled = !ready || client.busy;
  $("serviceControlUnit").disabled = client.busy;
  for (const action of Object.keys(SERVICE_ACTIONS)) {
    $("serviceControl" + action[0].toUpperCase() + action.slice(1)).disabled =
      !ready || !checked || protectedUnit || client.busy;
  }
  $("serviceControlPolicyHint").hidden = !protectedUnit;
  const badge = $("serviceControlBadge");
  badge.textContent = checked ? "Проверено" : ready ? "Нужна проверка" : "Нет доступа";
  badge.className = `status-badge${checked ? "" : " waiting"}`;
  if (client.control && !checked && !client.busy) $("serviceControlStatus").textContent = "Проверка устарела. Проверьте службу заново.";
}

function serviceControlValidateStatus(reply, unit) {
  const value = reply?.control;
  if (!value || value.unit !== unit || !["ok", "unavailable"].includes(value.source_status) ||
      (value.source_status === "ok" && (typeof value.active_state !== "string" ||
        typeof value.load_state !== "string" || typeof value.sub_state !== "string" ||
        !Number.isSafeInteger(value.observed_at)))) {
    throw new Error("Hub вернул неверное состояние службы.");
  }
  return value;
}

async function serviceControlQueue(payload) {
  const client = serviceControl;
  const serverId = client.serverId, token = state.token, base = state.base;
  if (!serverId || !token || !hubCanAdmin() || client.busy ||
      !serviceControlValidUnit(payload?.unit) ||
      (payload.action !== "status" && !Object.hasOwn(SERVICE_ACTIONS, payload.action))) return;
  if (payload.action !== "status" && (serviceControlProtectedUnit(payload.unit) ||
      client.control?.source_status !== "ok" || client.control.unit !== payload.unit ||
      client.unit !== payload.unit || $("serviceControlUnit").value.trim() !== payload.unit ||
      Date.now() - client.receivedAt >= 85000)) return;
  const server = state.servers.find((item) => String(item.id) === String(serverId));
  if (!server?.online || !server.remote_commands_enabled) return;
  const generation = client.generation;
  const existing = client.pending;
  const key = existing && JSON.stringify(existing.payload) === JSON.stringify(payload) ? existing.key : crypto.randomUUID();
  client.pending = { key, payload };
  client.busy = true;
  client.jobId = null;
  clearError($("serviceControlError"));
  $("serviceControlStatus").textContent = payload.action === "status" ? "Проверяем состояние…" : "Выполняем действие…";
  serviceControlRender();
  const current = () => serviceControlCurrent(generation, serverId, token, base) &&
    $("serviceControlUnit").value.trim() === payload.unit;
  try {
    const result = await request(`/api/v1/servers/${encodeURIComponent(serverId)}/services/actions`, {
      method: "POST", headers: { "Idempotency-Key": key }, body: JSON.stringify(payload), timeoutMs: 16000,
    });
    if (!current()) return;
    if (!result?.job?.id || String(result.job.server_id) !== String(serverId))
      throw new Error("Hub не вернул задание. Проверьте историю перед повтором.");
    client.jobId = result.job.id;
    const deadline = Date.now() + 85000;
    while (current() && Date.now() < deadline) {
      const reply = await request(`/api/v1/jobs/${encodeURIComponent(client.jobId)}`, { timeoutMs: 12000 });
      if (!current()) return;
      const job = reply?.job;
      if (!job || job.id !== client.jobId || String(job.server_id) !== String(serverId))
        throw new Error("Hub вернул другое задание.");
      if (SERVICE_TERMINAL.has(job.state)) {
        client.pending = null;
        client.control = null;
        client.receivedAt = 0;
        if (job.state === "timed_out")
          throw new Error("Время ожидания истекло. Действие могло выполниться; проверьте состояние снова.");
        if (job.state !== "succeeded")
          throw new Error("Служба не ответила. Проверьте локальные разрешения Agent.");
        if (payload.action === "status") {
          const status = serviceControlValidateStatus(await request(
            `/api/v1/servers/${encodeURIComponent(serverId)}/services/control?unit=${encodeURIComponent(payload.unit)}`), payload.unit);
          if (!current()) return;
          if (status.source_status !== "ok") throw new Error("Проверка завершилась, но результат уже устарел.");
          client.control = status;
          client.receivedAt = Date.now();
          client.unit = payload.unit;
          $("serviceControlStatus").textContent = `${payload.unit}: ${status.active_state} · ${status.sub_state} · проверено ${timestamp(status.observed_at)}.`;
        } else {
          $("serviceControlStatus").textContent = `${SERVICE_ACTIONS[payload.action]}: задание завершено. Проверьте состояние службы заново.`;
        }
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }
    if (current()) throw new Error("Ожидание завершилось. Проверьте состояние до нового действия.");
  } catch (error) {
    if (current()) {
      const rejectedBeforeQueue = payload.action !== "status" && !client.jobId &&
        [400, 403, 404, 409, 503].includes(error.status);
      if (payload.action !== "status") {
        // A delivered mutation may have taken effect even when its reply is
        // lost. Do not replay it from this dialog, including with the same key.
        client.pending = null;
        client.control = null;
        client.receivedAt = 0;
        $("serviceControlStatus").textContent = rejectedBeforeQueue
          ? "Действие отклонено. Проверьте разрешения службы и её состояние."
          : "Исход действия нужно проверить. Запросите новое состояние службы.";
      }
      showError($("serviceControlError"), error.status === 404 ?
        "Обновите Hub и Agent для управления службами." : rejectedBeforeQueue ?
          "Hub отклонил действие до постановки в очередь. Проверьте разрешения службы." : payload.action !== "status" ?
          "Действие могло выполниться. Проверьте состояние службы до новой операции." :
            error.message || "Не удалось проверить службу.");
    }
  } finally {
    if (current()) { client.busy = false; serviceControlRender(); }
  }
}

function serviceControlPrepare(action) {
  const client = serviceControl;
  const unit = $("serviceControlUnit").value.trim();
  if (serviceControlProtectedUnit(unit)) {
    showError($("serviceControlError"), "Эта служба доступна только для проверки состояния."); return;
  }
  if (client.control?.unit === unit && Date.now() - client.receivedAt >= 85000) {
    client.control = null;
    serviceControlRender();
    showError($("serviceControlError"), "Проверка устарела. Проверьте службу заново.");
    return;
  }
  if (!Object.hasOwn(SERVICE_ACTIONS, action) || !serviceControlValidUnit(unit) ||
      client.control?.source_status !== "ok" || client.control.unit !== unit ||
      Date.now() - client.receivedAt >= 85000 || client.busy) return;
  const server = state.servers.find((item) => String(item.id) === String(client.serverId));
  if (!server || !hubCanAdmin() || !server.online || !server.remote_commands_enabled) return;
  client.confirmation = { action, unit, serverId: server.id, generation: client.generation,
    token: state.token, base: state.base };
  $("serviceControlDialogTitle").textContent = `${SERVICE_ACTIONS[action]} службу?`;
  $("serviceControlDialogSummary").textContent = `${unit} · состояние сейчас: ${client.control.active_state}`;
  $("serviceControlDialogServer").textContent = `Сервер: ${server.name || server.id}`;
  clearError($("serviceControlDialogError"));
  $("serviceControlDialog").showModal();
}

async function serviceControlConfirm() {
  const pending = serviceControl.confirmation;
  if (!pending) return;
  const server = state.servers.find((item) => String(item.id) === String(pending.serverId));
  if (pending.generation !== serviceControl.generation ||
      !serviceControlCurrent(pending.generation, pending.serverId, pending.token, pending.base) ||
      !hubCanAdmin() || !server?.online || !server.remote_commands_enabled ||
      serviceControl.control?.source_status !== "ok" || serviceControl.control.unit !== pending.unit ||
      serviceControl.unit !== pending.unit || serviceControlProtectedUnit(pending.unit) ||
      serviceControl.busy ||
      $("serviceControlUnit").value.trim() !== pending.unit ||
      Date.now() - serviceControl.receivedAt >= 85000) {
    showError($("serviceControlDialogError"), "Состояние изменилось. Проверьте службу заново."); return;
  }
  $("serviceControlConfirm").disabled = true;
  $("serviceControlCancel").disabled = true;
  try {
    await serviceControlQueue({ action: pending.action, unit: pending.unit });
    if (serviceControl.confirmation === pending && !serviceControl.pending) $("serviceControlDialog").close();
    else if (serviceControl.confirmation === pending)
      showError($("serviceControlDialogError"), "Операция не подтверждена. Проверьте состояние службы перед новым действием.");
  } finally {
    if (serviceControl.confirmation === pending) {
      $("serviceControlConfirm").disabled = false;
      $("serviceControlCancel").disabled = false;
    }
  }
}

$("serviceControlForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const unit = $("serviceControlUnit").value.trim();
  if (!serviceControlValidUnit(unit)) {
    showError($("serviceControlError"), "Введите точное имя службы вида nginx.service."); return;
  }
  serviceControl.control = null;
  serviceControl.receivedAt = 0;
  serviceControl.unit = unit;
  void serviceControlQueue({ action: "status", unit });
});
$("serviceControlUnit").addEventListener("input", () => {
  serviceControl.control = null;
  serviceControl.receivedAt = 0;
  serviceControlRender();
});
for (const action of Object.keys(SERVICE_ACTIONS)) {
  $("serviceControl" + action[0].toUpperCase() + action.slice(1)).addEventListener("click", () => serviceControlPrepare(action));
}
$("serviceControlConfirm").addEventListener("click", serviceControlConfirm);
$("serviceControlCancel").addEventListener("click", () => { if (!serviceControl.busy) $("serviceControlDialog").close(); });
$("serviceControlDialog").addEventListener("cancel", (event) => { if (serviceControl.busy) event.preventDefault(); });
$("serviceControlDialog").addEventListener("close", () => { if (!serviceControl.busy) serviceControl.confirmation = null; });

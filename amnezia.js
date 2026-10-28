/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// Amnezia management is opt-in on each Agent. This tab holds the only copy of
// the profile recipient key and plaintext File; neither is persisted.
const amneziaClient = {
  generation: 0, controlSeq: 0, serverId: null, target: "awg2", control: null, jobId: null, job: null,
  jobAction: null, settingsPreview: null, settingsPreviewError: null,
  settingsPlan: null, settingsPlanError: null, planPending: null, planRequest: null,
  intentPending: null, intentRequest: null, intentExpiryTimer: null,
  applyRequest: null, applyExpectation: null, settingsApplyOutcome: null,
  pending: null, submittingKey: null, polling: null, preparing: false,
  profile: null, downloadUrls: new Set(),
};
const AMNEZIA_CLIENT_NAME = /^[a-z][a-z0-9_-]{0,31}$/;
const AMNEZIA_TERMINAL_STATES = new Set(["succeeded", "failed", "timed_out", "output_limited", "cancelled"]);
const AMNEZIA_TARGETS = { awg2: { label: "AmneziaWG", format: "awg3-conf" },
  wireguard: { label: "WireGuard", format: "wg-conf" } };
const AMNEZIA_PREVIEW_FIELDS = ["target", "container_id", "image_id", "config_sha256", "table_sha256",
  "generation", "protocol", "interface", "listen_port", "server_address", "server_subnet",
  "configured_clients", "managed_clients", "external_clients", "awg_parameters",
  "awg_parameters_runtime_verified", "header_protection_key_present",
  "awg3_required_parameters_present", "apply_supported", "apply_blockers"].sort();
const AMNEZIA_AWG_NUMBERS = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"];
const AMNEZIA_AWG_RANGES = ["H1", "H2", "H3", "H4"];
const AMNEZIA_AWG_FIELDS = [...AMNEZIA_AWG_NUMBERS, ...AMNEZIA_AWG_RANGES];
const AMNEZIA_PREVIEW_BLOCKERS = ["CLIENT_PROFILES_REQUIRE_REISSUE",
  "PORT_REQUIRES_CONTAINER_NETWORK_MIGRATION"];
const AMNEZIA_PLAN_FIELDS = ["target", "container_id", "image_id", "generation", "config_sha256",
  "table_sha256", "proposed_config_sha256", "current_awg_parameters", "proposed_awg_parameters",
  "changed_fields", "configured_clients", "apply_supported", "apply_blockers"].sort();

function amneziaParseSettingsPreview(raw, target) {
  if (typeof raw !== "string" || new TextEncoder().encode(raw).length > 4096) return null;
  let value;
  try { value = JSON.parse(raw); } catch { return null; }
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(AMNEZIA_PREVIEW_FIELDS) ||
      value.target !== target) return null;
  for (const field of ["container_id", "config_sha256", "table_sha256"]) {
    if (typeof value[field] !== "string" || !/^[0-9a-f]{64}$/.test(value[field])) return null;
  }
  if (typeof value.image_id !== "string" || !/^sha256:[0-9a-f]{64}$/.test(value.image_id) ||
      value.protocol !== (target === "awg2" ? "amneziawg" : "wireguard") ||
      value.interface !== (target === "awg2" ? "awg0" : "wg0")) return null;
  const ipv4 = (address) => typeof address === "string" && address.split(".").length === 4 &&
    address.split(".").every((part) => /^(0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255);
  const [network, prefix] = typeof value.server_subnet === "string" ? value.server_subnet.split("/") : [];
  if (!ipv4(value.server_address) || !ipv4(network) || !/^(0|[1-9]|[12][0-9]|3[0-2])$/.test(prefix || "")) return null;
  const addressBits = (address) => address.split(".").reduce((bits, octet) =>
    ((bits << 8) | Number(octet)) >>> 0, 0);
  const mask = Number(prefix) === 0 ? 0 : (0xffffffff << (32 - Number(prefix))) >>> 0;
  if (((addressBits(network) & mask) >>> 0) !== addressBits(network) ||
      ((addressBits(value.server_address) & mask) >>> 0) !== addressBits(network)) return null;
  for (const [field, maximum] of [["generation", 1e9], ["listen_port", 65535],
    ["configured_clients", 2048], ["managed_clients", 2048], ["external_clients", 2048]]) {
    if (!Number.isSafeInteger(value[field]) || value[field] < 0 || value[field] > maximum) return null;
  }
  if (value.listen_port === 0 || value.managed_clients + value.external_clients !== value.configured_clients ||
      value.awg_parameters_runtime_verified !== false || value.apply_supported !== false ||
      typeof value.header_protection_key_present !== "boolean" ||
      typeof value.awg3_required_parameters_present !== "boolean" ||
      JSON.stringify(value.apply_blockers) !== JSON.stringify(AMNEZIA_PREVIEW_BLOCKERS)) return null;
  const params = value.awg_parameters;
  if (!params || typeof params !== "object" || Array.isArray(params) ||
      Object.keys(params).some((name) => ![...AMNEZIA_AWG_NUMBERS, ...AMNEZIA_AWG_RANGES].includes(name))) return null;
  for (const [name, number] of Object.entries(params)) {
    if (typeof number !== "string" || !/^[0-9]{1,10}(?:-[0-9]{1,10})?$/.test(number)) return null;
    const parts = number.split("-").map(Number);
    if (Math.max(...parts) > (AMNEZIA_AWG_NUMBERS.includes(name) ? 65535 : 4294967295) ||
        (parts.length === 2 && (AMNEZIA_AWG_NUMBERS.includes(name) || parts[0] > parts[1]))) return null;
  }
  if (params.Jmin !== undefined && params.Jmax !== undefined && Number(params.Jmin) > Number(params.Jmax)) return null;
  const required = [...AMNEZIA_AWG_NUMBERS, ...AMNEZIA_AWG_RANGES].every((name) => Object.hasOwn(params, name)) &&
    value.header_protection_key_present;
  if (target === "wireguard" ? Object.keys(params).length || value.header_protection_key_present ||
      value.awg3_required_parameters_present : value.awg3_required_parameters_present !== required) return null;
  return value;
}

function amneziaValidAwgParameter(name, value, canonical = false) {
  if (!AMNEZIA_AWG_FIELDS.includes(name) || typeof value !== "string" ||
      !/^[0-9]{1,10}(?:-[0-9]{1,10})?$/.test(value)) return false;
  const parts = value.split("-").map(Number);
  return Math.max(...parts) <= (AMNEZIA_AWG_NUMBERS.includes(name) ? 65535 : 4294967295) &&
    (parts.length === 1 || (!AMNEZIA_AWG_NUMBERS.includes(name) && parts[0] <= parts[1])) &&
    (!canonical || value === parts.join("-"));
}

function amneziaParseSettingsPlan(raw, preview, patch) {
  if (!preview || preview.target !== "awg2" || typeof raw !== "string" ||
      new TextEncoder().encode(raw).length > 4096) return null;
  let value;
  try { value = JSON.parse(raw); } catch { return null; }
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(AMNEZIA_PLAN_FIELDS) ||
      value.target !== "awg2" || typeof value.apply_supported !== "boolean") return null;
  for (const field of ["container_id", "config_sha256", "table_sha256", "proposed_config_sha256"]) {
    if (typeof value[field] !== "string" || !/^[0-9a-f]{64}$/.test(value[field])) return null;
  }
  if (value.container_id !== preview.container_id || value.config_sha256 !== preview.config_sha256 ||
      value.table_sha256 !== preview.table_sha256 || value.proposed_config_sha256 === preview.config_sha256 ||
      value.image_id !== preview.image_id || value.generation !== preview.generation ||
      value.configured_clients !== preview.configured_clients) return null;
  const current = value.current_awg_parameters, proposed = value.proposed_awg_parameters;
  if (!current || !proposed || typeof current !== "object" || typeof proposed !== "object" ||
      Array.isArray(current) || Array.isArray(proposed) ||
      JSON.stringify(Object.keys(current).sort()) !== JSON.stringify([...AMNEZIA_AWG_FIELDS].sort()) ||
      JSON.stringify(Object.keys(proposed).sort()) !== JSON.stringify([...AMNEZIA_AWG_FIELDS].sort())) return null;
  for (const name of AMNEZIA_AWG_FIELDS) {
    if (!amneziaValidAwgParameter(name, current[name]) || !amneziaValidAwgParameter(name, proposed[name]) ||
        current[name] !== preview.awg_parameters[name] ||
        proposed[name] !== (Object.hasOwn(patch, name) ? patch[name] : current[name])) return null;
  }
  const changed = AMNEZIA_AWG_FIELDS.filter((name) => current[name] !== proposed[name]).sort();
  if (!changed.length || JSON.stringify(value.changed_fields) !== JSON.stringify(changed) ||
      JSON.stringify(changed) !== JSON.stringify(Object.keys(patch).sort()) ||
      Number(proposed.Jmin) > Number(proposed.Jmax) ||
      ["S1", "S2", "S3", "S4"].some((name) => Number(proposed[name]) < 12)) return null;
  const blockers = preview.configured_clients > 0 ? ["CLIENT_PROFILES_REQUIRE_REISSUE"] : [];
  if (value.apply_supported !== (preview.configured_clients === 0) ||
      JSON.stringify(value.apply_blockers) !== JSON.stringify(blockers)) return null;
  return value;
}

function amneziaParseSettingsIntent(raw, plan) {
  if (!plan?.apply_supported || plan.configured_clients !== 0 ||
      typeof raw !== "string" || new TextEncoder().encode(raw).length > 4096) return null;
  let value;
  try { value = JSON.parse(raw); } catch { return null; }
  const fields = ["target", "action", "confirmation_id", "expires_at", "generation",
    "config_sha256", "proposed_config_sha256", "changed_fields", "configured_clients"].sort();
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(fields) ||
      value.target !== "awg2" || value.action !== "settings_intent" ||
      typeof value.confirmation_id !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value.confirmation_id) ||
      !Number.isSafeInteger(value.expires_at) || value.expires_at < 1 ||
      value.generation !== plan.generation || value.config_sha256 !== plan.config_sha256 ||
      value.proposed_config_sha256 !== plan.proposed_config_sha256 ||
      value.configured_clients !== 0 ||
      JSON.stringify(value.changed_fields) !== JSON.stringify(plan.changed_fields)) return null;
  try { base64UrlDecode(value.confirmation_id, 32); } catch { return null; }
  return value;
}

function amneziaParseSettingsApplied(raw, request) {
  if (!request || typeof raw !== "string" || new TextEncoder().encode(raw).length > 4096) return null;
  let value;
  try { value = JSON.parse(raw); } catch { return null; }
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(
        ["target", "action", "generation", "config_sha256", "cleanup_required"].sort()) ||
      value.target !== "awg2" || value.action !== "settings_updated" ||
      value.generation !== request.plan.generation + 1 ||
      value.config_sha256 !== request.plan.proposed_config_sha256 ||
      typeof value.cleanup_required !== "boolean") return null;
  return value;
}
function selectedAmneziaTarget() { return Object.hasOwn(AMNEZIA_TARGETS, $("amneziaTarget").value)
  ? $("amneziaTarget").value : "awg2"; }

function amneziaReset() {
  if (amneziaClient.intentExpiryTimer !== null) clearTimeout(amneziaClient.intentExpiryTimer);
  amneziaClient.generation++;
  amneziaClient.controlSeq++;
  amneziaClient.serverId = null;
  amneziaClient.target = selectedAmneziaTarget();
  amneziaClient.control = null;
  amneziaClient.jobId = null;
  amneziaClient.job = null;
  amneziaClient.jobAction = null;
  amneziaClient.settingsPreview = null;
  amneziaClient.settingsPreviewError = null;
  amneziaClient.settingsPlan = null;
  amneziaClient.settingsPlanError = null;
  amneziaClient.planPending = null;
  amneziaClient.planRequest = null;
  amneziaClient.intentPending = null;
  amneziaClient.intentRequest = null;
  amneziaClient.intentExpiryTimer = null;
  amneziaClient.applyRequest = null;
  amneziaClient.applyExpectation = null;
  amneziaClient.settingsApplyOutcome = null;
  amneziaClient.pending = null;
  amneziaClient.submittingKey = null;
  amneziaClient.polling = null;
  amneziaClient.preparing = false;
  amneziaClient.profile = null;
  for (const url of amneziaClient.downloadUrls) URL.revokeObjectURL(url);
  amneziaClient.downloadUrls.clear();
  if ($("amneziaDialog").open) $("amneziaDialog").close();
  $("amneziaRevokeName").value = "";
  $("amneziaJobPanel").hidden = true;
  $("amneziaProfileStatus").textContent = "";
  clearError($("amneziaPlanError"));
  amneziaPlanInputsFromPreview(null);
  $("amneziaDownload").hidden = true;
  $("amneziaShare").hidden = true;
  clearError($("amneziaError"));
  clearError($("amneziaDialogError"));
  renderAmneziaControl();
}
globalThis.amneziaReset = amneziaReset;

function amneziaCurrent(generation, serverId, token, base) {
  return amneziaClient.generation === generation &&
    String(amneziaClient.serverId) === String(serverId) &&
    String(state.vpnTargetId) === String(serverId) &&
    state.token === token && state.base === base && Boolean(token);
}

function amneziaCanMutate() {
  const control = amneziaClient.control;
  return vpnTargetReady() && String(amneziaClient.serverId) === String(state.vpnTargetId) &&
    control?.source_status === "ok" &&
    control.target === amneziaClient.target && control.enrolled === true &&
    control.recovery_required === false;
}

function amneziaProfileCurrent(profile) {
  return amneziaClient.profile === profile &&
    amneziaCurrent(profile.generation, profile.serverId, profile.token, profile.base);
}

function renderAmneziaControl() {
  const server = vpnTarget(), control = amneziaClient.control;
  const label = AMNEZIA_TARGETS[amneziaClient.target].label;
  $("amneziaAddHeading").textContent = `Создать профиль ${amneziaClient.target === "awg2" ? "AmneziaWG 3.1" : "WireGuard"}`;
  const ready = amneziaCanMutate();
  const badge = $("amneziaControlBadge");
  badge.textContent = ready ? "Управление доступно" : control?.recovery_required ? "Нужна проверка" : "Нет доступа";
  badge.className = `status-badge ${ready ? "" : control?.recovery_required ? "vpn-status-error" : "vpn-status-unavailable"}`;
  $("amneziaControlText").textContent = !server ? "Выберите сервер для операций WireGuard ниже." :
    !server.online ? "Agent не на связи. Управление профилями недоступно." :
      !server.remote_commands_enabled ? `Разрешите команды для этого сервера в Hub перед проверкой ${label}.` :
        control?.recovery_required ? "Локальный брокер требует восстановления. Обратитесь к администратору сервера; операции заблокированы." :
          ready ? `Локальный брокер ${label} доступен. Операции касаются только клиентов, добавленных SovaGrid на выбранном сервере.` :
            `Локальный брокер ${label} выключен или ещё не проверен. Настройка доступна администратору в SovaGrid Connect, в разделе «Управление Amnezia».`;
  $("amneziaObserved").textContent = control?.observed_at ? `Проверено: ${timestamp(control.observed_at)}` : "Состояние не проверено";
  const jobRunning = amneziaClient.jobId && !AMNEZIA_TERMINAL_STATES.has(amneziaClient.job?.state);
  const profileBusy = ["pending", "decrypting"].includes(amneziaClient.profile?.status);
  $("amneziaCheck").disabled = !vpnTargetReady() || Boolean(amneziaClient.submittingKey || jobRunning || profileBusy);
  $("amneziaSettingsPreview").disabled = !ready || amneziaClient.preparing ||
    Boolean(amneziaClient.submittingKey || jobRunning || profileBusy);
  for (const id of ["amneziaAddButton", "amneziaExportButton", "amneziaRevokeButton"]) {
    $(id).disabled = !ready || amneziaClient.preparing || Boolean(amneziaClient.submittingKey || jobRunning || profileBusy);
  }
  const owned = $("amneziaOwned");
  owned.replaceChildren();
  if (!ready) {
    owned.textContent = "Список доступен после успешной проверки локального брокера.";
  } else if (!control.owned_clients.length) {
    owned.textContent = "Клиентов SovaGrid пока нет.";
  } else {
    const list = document.createElement("ul");
    for (const client of control.owned_clients) {
      const item = document.createElement("li");
      item.textContent = client;
      list.append(item);
    }
    owned.append(list);
  }
  renderAmneziaSettingsPreview();
  renderAmneziaPlan();
  renderAmneziaJob();
}

function renderAmneziaSettingsPreview() {
  const preview = amneziaClient.settingsPreview, error = amneziaClient.settingsPreviewError;
  const card = $("amneziaSettingsCard");
  card.hidden = !preview && !error && amneziaClient.settingsApplyOutcome !== "uncertain";
  if (!preview) {
    $("amneziaSettingsState").textContent = amneziaClient.settingsApplyOutcome === "uncertain"
      ? `Состояние изменения неизвестно. Сверьте состояние брокера и снимок сервера. ${error || ""}` : error || "";
    $("amneziaSettingsValues").textContent = "";
    $("amneziaSettingsDigests").textContent = "";
    $("amneziaSettingsDetails").hidden = true;
    return;
  }
  $("amneziaSettingsState").textContent = (amneziaClient.settingsApplyOutcome === "uncertain"
    ? "Состояние изменения неизвестно. Сверьте свежий снимок и состояние брокера; не повторяйте применение вслепую. " : "") + (preview.configured_clients === 0
    ? "Снимок только для просмотра. Для изменения числовых параметров AWG3 подготовьте план и подтвердите применение. Доступность UDP-порта снаружи этим снимком не проверяется."
    : "Снимок только для просмотра. Изменение настроек потребует отдельной миграции и перевыпуска клиентских профилей. Доступность UDP-порта снаружи этим снимком не проверяется.");
  const rows = [
    `Протокол: ${AMNEZIA_TARGETS[preview.target].label}`,
    `Интерфейс: ${preview.interface}`,
    `Адрес сервера: ${preview.server_address}`,
    `Подсеть VPN: ${preview.server_subnet}`,
    `Порт: ${preview.listen_port}/UDP`,
    `Клиенты: ${preview.configured_clients} всего · ${preview.managed_clients} SovaGrid · ${preview.external_clients} внешних`,
  ];
  if (preview.target === "awg2") {
    rows.push(`Параметры AWG: ${[...AMNEZIA_AWG_NUMBERS, ...AMNEZIA_AWG_RANGES]
      .filter((name) => Object.hasOwn(preview.awg_parameters, name))
      .map((name) => `${name}=${preview.awg_parameters[name]}`).join(" · ") || "не заданы"}`);
    rows.push(`Параметры AWG 3.1 в файле: ${preview.awg3_required_parameters_present ? "полный набор" : "неполный набор"}`);
    rows.push("Работающие параметры AWG не подтверждены интерфейсом.");
  }
  $("amneziaSettingsValues").textContent = rows.join("\n");
  $("amneziaSettingsDetails").hidden = false;
  $("amneziaSettingsDigests").textContent = `Контейнер: ${preview.container_id}\nОбраз: ${preview.image_id}\nSHA-256 конфигурации: ${preview.config_sha256}\nSHA-256 таблицы клиентов: ${preview.table_sha256}\nПоколение: ${preview.generation}`;
}

function amneziaPlanInputsFromPreview(preview) {
  for (const name of AMNEZIA_AWG_FIELDS) {
    $("amneziaPlan" + name).value = preview?.awg_parameters?.[name] || "";
  }
}

function amneziaCanPlan() {
  const preview = amneziaClient.settingsPreview;
  return amneziaCanMutate() && amneziaClient.target === "awg2" && preview?.target === "awg2" &&
    preview.awg3_required_parameters_present === true && preview.header_protection_key_present === true &&
    AMNEZIA_AWG_FIELDS.every((name) => amneziaValidAwgParameter(name, preview.awg_parameters[name]));
}

function amneziaCanApplyPlan() {
  const plan = amneziaClient.settingsPlan, request = amneziaClient.planRequest;
  if (state.view !== "vpn" || !amneziaCanPlan() || !plan?.apply_supported || plan.configured_clients !== 0 ||
      !Array.isArray(plan.apply_blockers) || plan.apply_blockers.length ||
      request?.preview !== amneziaClient.settingsPreview ||
      plan.target !== "awg2" || plan.config_sha256 !== request.preview.config_sha256 ||
      plan.generation !== request.preview.generation) return false;
  const current = amneziaPlanProposal(request.preview);
  return !current.error && JSON.stringify(Object.entries(current.patch).sort()) ===
    JSON.stringify(Object.entries(request.patch).sort());
}

function renderAmneziaPlan() {
  const available = amneziaCanPlan();
  $("amneziaPlanSection").hidden = !available;
  const jobRunning = amneziaClient.jobId && !AMNEZIA_TERMINAL_STATES.has(amneziaClient.job?.state);
  const profileBusy = ["pending", "decrypting"].includes(amneziaClient.profile?.status);
  const busy = Boolean(amneziaClient.submittingKey || jobRunning || profileBusy ||
    amneziaClient.preparing || $("amneziaDialog").open);
  for (const name of AMNEZIA_AWG_FIELDS) {
    $("amneziaPlan" + name).disabled = !available || busy || Boolean(amneziaClient.planPending);
  }
  $("amneziaPlanSubmit").disabled = !available || busy;
  $("amneziaPlanSubmit").textContent = amneziaClient.planPending
    ? "Повторить запрос с тем же ключом" : "Показать план";
  $("amneziaPlanReset").disabled = !available || busy;
  const plan = amneziaClient.settingsPlan;
  $("amneziaPlanResult").hidden = !available || !plan;
  $("amneziaPlanPrepareApply").hidden = !plan?.apply_supported;
  $("amneziaPlanPrepareApply").disabled = busy || !amneziaCanApplyPlan();
  $("amneziaPlanPrepareApply").textContent = amneziaClient.intentPending
    ? "Повторить запрос подтверждения" : "Подготовить применение";
  if (!plan) {
    $("amneziaPlanResultState").textContent = "";
    $("amneziaPlanSummary").textContent = "";
    $("amneziaPlanBlockers").textContent = "";
    $("amneziaPlanDigests").textContent = "";
    return;
  }
  const changes = plan.changed_fields.map((name) =>
    `${name}: ${plan.current_awg_parameters[name]} → ${plan.proposed_awg_parameters[name]}`);
  $("amneziaPlanResultState").textContent = plan.apply_supported
    ? "План для применения после отдельного подтверждения"
    : "План только для просмотра";
  $("amneziaPlanSummary").textContent = `Изменятся: ${changes.join(" · ")}. Клиентов: ${plan.configured_clients}. Файл и работающий интерфейс не изменены.`;
  $("amneziaPlanBlockers").textContent = plan.apply_supported
    ? "Для применения администратор должен отдельно включить «Изменение AWG3» в Connect. После запроса потребуется ещё одно подтверждение; порт и ключи сервера не изменятся."
    : "Применение недоступно: действующим клиентам понадобятся новые профили. Этот сценарий пока не поддерживается.";
  $("amneziaPlanDigests").textContent = `Текущая конфигурация: ${plan.config_sha256}\nРасчётная конфигурация: ${plan.proposed_config_sha256}\nПоколение: ${plan.generation}`;
}

function renderAmneziaJob() {
  $("amneziaJobPanel").hidden = !amneziaClient.jobId;
  if (!amneziaClient.jobId) return;
  const job = amneziaClient.job, profile = amneziaClient.profile;
  $("amneziaJobState").textContent = `Задание ${amneziaClient.jobId}: ${job ? jobState(job) : "В очереди"}.`;
  const status = $("amneziaProfileStatus");
  status.textContent = job?.state === "failed" && amneziaClient.jobAction === "settings-intent"
    ? "Подтверждение не получено. Проверьте отдельное разрешение «Изменение AWG3» в Connect и состояние брокера." :
    job?.state === "failed" && amneziaClient.jobAction === "status"
      ? "Брокер Amnezia на сервере не настроен или не отвечает. Проверьте его в разделе «Управление Amnezia» SovaGrid Connect." :
    job?.state === "failed" ? "Операция не выполнена. Проверьте локальное состояние брокера и повторите проверку." :
    job?.state === "timed_out" ? "Время ожидания истекло. Перед новой операцией проверьте состояние сервера." :
      job?.state === "succeeded" && amneziaClient.jobAction === "settings-preview" ?
        (amneziaClient.settingsPreview ? (amneziaClient.settingsApplyOutcome === "applied"
          ? "Настройки AWG3 применены; снимок сервера обновлён." :
          amneziaClient.settingsApplyOutcome === "uncertain" ? "Состояние изменения неизвестно. Сверьте свежий снимок и состояние брокера." :
            "Настройки показаны выше.")
          : "Ответ настроек не прошёл проверку.") :
      job?.state === "succeeded" && amneziaClient.jobAction === "settings-plan" ?
        (amneziaClient.settingsPlan ? "План показан выше. Сервер не изменён." : "Ответ плана не прошёл проверку.") :
      job?.state === "succeeded" && amneziaClient.jobAction === "settings-intent" ?
        (amneziaClient.pending?.kind === "settings-apply" ? "Проверьте изменения в окне подтверждения." :
          "Ответ подтверждения не прошёл проверку.") :
      job?.state === "succeeded" && amneziaClient.jobAction === "settings-apply" ?
        (amneziaClient.settingsApplyOutcome === "refreshing" ? "Брокер подтвердил изменение. Проверяем свежий снимок сервера." :
          "Результат не подтверждён. Проверьте состояние сервера перед новым запросом.") :
      job?.state === "succeeded" && !profile ? "Операция завершена. Обновите состояние управления." : "";
  $("amneziaDownload").hidden = true;
  $("amneziaShare").hidden = true;
  if (!profile || !amneziaProfileCurrent(profile)) return;
  if (profile.status === "ready") {
    status.textContent = job?.state === "failed"
      ? "Последняя операция завершилась ошибкой. Ранее полученный профиль остаётся доступен в этой вкладке."
      : "Профиль расшифрован в этой вкладке. Сохраните его на своё устройство.";
    $("amneziaDownload").hidden = false;
    try { $("amneziaShare").hidden = !navigator.canShare?.({ files: [profile.file] }); }
    catch { $("amneziaShare").hidden = true; }
  } else if (profile.jobId === amneziaClient.jobId) {
    if (profile.status === "decrypting") status.textContent = "Расшифровываем профиль на этом устройстве…";
    else if (profile.status === "failed") status.textContent = "Не удалось открыть профиль. Запросите защищённую выдачу ещё раз.";
    else if (job?.state === "succeeded") status.textContent = "Подготавливаем защищённый профиль…";
    else if (!AMNEZIA_TERMINAL_STATES.has(job?.state)) status.textContent = "Ожидаем зашифрованный профиль. Не закрывайте эту вкладку.";
  }
}

function amneziaTargetChanged() {
  const serverId = vpnTarget()?.id ?? null;
  const target = selectedAmneziaTarget();
  if (String(amneziaClient.serverId) === String(serverId) && amneziaClient.target === target) {
    renderAmneziaControl();
    return;
  }
  amneziaReset();
  amneziaClient.serverId = serverId;
  amneziaClient.target = target;
  renderAmneziaControl();
  if (serverId && state.token && state.view === "vpn") void amneziaLoadControl();
}
globalThis.amneziaTargetChanged = amneziaTargetChanged;

async function amneziaLoadControl() {
  if (!amneziaClient.serverId || !state.token || state.view !== "vpn") return;
  const generation = amneziaClient.generation, serverId = amneziaClient.serverId;
  const target = amneziaClient.target;
  const token = state.token, base = state.base;
  const sequence = ++amneziaClient.controlSeq;
  try {
    const reply = await request(`/api/v1/servers/${encodeURIComponent(serverId)}/amnezia/control${target === "awg2" ? "" : "?target=wireguard"}`, { timeoutMs: 12000 });
    if (!amneziaCurrent(generation, serverId, token, base) || sequence !== amneziaClient.controlSeq) return;
    const control = reply?.control;
    if (!control || !["ok", "unavailable"].includes(control.source_status) || control.target !== target ||
        typeof control.enrolled !== "boolean" || typeof control.recovery_required !== "boolean" ||
        !Array.isArray(control.owned_clients) || control.owned_clients.some((client) => !AMNEZIA_CLIENT_NAME.test(client))) {
      throw new Error("Центр мониторинга вернул неверное состояние VPN-контейнера.");
    }
    amneziaClient.control = control;
    if (!["uncertain", "refreshing"].includes(amneziaClient.settingsApplyOutcome))
      clearError($("amneziaError"));
    renderAmneziaControl();
  } catch (error) {
    if (!amneziaCurrent(generation, serverId, token, base) || sequence !== amneziaClient.controlSeq) return;
    amneziaClient.control = null;
    renderAmneziaControl();
    showError($("amneziaError"), error.status === 404 ? "Этот сервер больше не зарегистрирован." :
      error.message || "Не удалось проверить управление VPN-контейнером.");
  }
}

function amneziaValidClient(client) { return AMNEZIA_CLIENT_NAME.test(client); }

function amneziaOpenConfirmation(payload, privateKey = null) {
  const server = vpnTarget();
  if (!server || String(server.id) !== String(amneziaClient.serverId) || !amneziaCanMutate()) {
    showError($("amneziaError"), "Управление VPN-контейнером недоступно. Проверьте локальный брокер заново.");
    return;
  }
  const key = crypto.randomUUID();
  amneziaClient.pending = { payload, key, privateKey, serverId: server.id,
    token: state.token, base: state.base };
  const label = AMNEZIA_TARGETS[payload.target]?.label || "VPN";
  $("amneziaDialogTitle").textContent = payload.action === "add-profile" ? `Создать профиль ${label}` :
    payload.action === "sealed-export" ? `Получить профиль ${label}` :
      payload.action === "settings-apply" ? "Применить настройки AWG3" : `Отозвать профиль ${label}`;
  $("amneziaDialogSummary").textContent = payload.action === "add-profile"
    ? `${payload.client} · ${payload.address} · ${payload.endpoint_host} · ${payload.route === "full" ? "весь трафик" : "только VPN"}`
    : payload.action === "settings-apply" ? "Проверьте изменение и подтвердите его для выбранного сервера." :
      `Клиент: ${payload.client}`;
  $("amneziaDialogServer").textContent = `Сервер: ${String(server.name || server.id)}`;
  $("amneziaRevokeConfirmation").hidden = payload.action !== "revoke";
  $("amneziaRevokeName").value = "";
  $("amneziaDialogConfirm").textContent = "Выполнить";
  $("amneziaDialogConfirm").disabled = payload.action === "revoke";
  clearError($("amneziaDialogError"));
  $("amneziaDialog").showModal();
}

function amneziaOpenSettingsConfirmation(intent, request) {
  if (request?.plan !== amneziaClient.settingsPlan ||
      request?.preview !== amneziaClient.settingsPreview || !amneziaCanApplyPlan()) return false;
  const plan = request.plan;
  const payload = { action: "settings-apply", target: "awg2",
    expected_config_sha256: plan.config_sha256,
    expected_generation: plan.generation,
    expected_proposed_config_sha256: plan.proposed_config_sha256,
    parameters: request.patch, confirmation_id: intent.confirmation_id };
  amneziaOpenConfirmation(payload);
  if (!amneziaClient.pending || !$("amneziaDialog").open) return false;
  Object.assign(amneziaClient.pending, { kind: "settings-apply", plan,
    preview: request.preview, patch: request.patch, intent, receivedAt: Date.now() });
  const pending = amneziaClient.pending;
  // The server enforces its own five-minute UTC expiry. Discard the browser's
  // short-lived handle sooner, without relying on matching client/server clocks.
  if (amneziaClient.intentExpiryTimer !== null) clearTimeout(amneziaClient.intentExpiryTimer);
  amneziaClient.intentExpiryTimer = setTimeout(() => {
    if (amneziaClient.pending === pending && !amneziaClient.submittingKey) {
      $("amneziaDialog").close();
      showError($("amneziaPlanError"), "Подтверждение истекло. Сверьте снимок и запросите новое.");
    }
  }, 240000);
  amneziaClient.intentExpiryTimer?.unref?.();
  const changes = plan.changed_fields.map((name) =>
    `${name}: ${plan.current_awg_parameters[name]} → ${plan.proposed_awg_parameters[name]}`);
  $("amneziaDialogSummary").textContent = `Изменятся параметры ${changes.join(" · ")}. Клиентов: 0. Порт и ключи сервера останутся прежними. Подтверждение действует пять минут.`;
  $("amneziaDialogConfirm").textContent = "Применить настройки";
  renderAmneziaControl();
  return true;
}

async function amneziaPrepareSealed(action, fields) {
  if (!amneziaCanMutate() || !globalThis.isSecureContext || !crypto?.subtle) {
    showError($("amneziaError"), "Проверьте брокер и откройте панель через HTTPS или localhost.");
    return;
  }
  const generation = amneziaClient.generation, serverId = amneziaClient.serverId;
  const token = state.token, base = state.base;
  amneziaClient.preparing = true;
  renderAmneziaControl();
  try {
    const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const publicBytes = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    if (!amneziaCurrent(generation, serverId, token, base)) return;
    if (publicBytes.length !== 65 || publicBytes[0] !== 4) throw new Error("Неверный ключ выдачи профиля.");
    amneziaOpenConfirmation({ action, target: amneziaClient.target, ...fields,
      public_key: base64UrlEncode(publicBytes) }, pair.privateKey);
  } catch {
    if (amneziaCurrent(generation, serverId, token, base)) {
      showError($("amneziaError"), "Не удалось создать ключ выдачи. Попробуйте обновить страницу.");
    }
  } finally {
    if (amneziaCurrent(generation, serverId, token, base)) {
      amneziaClient.preparing = false;
      renderAmneziaControl();
    }
  }
}

function amneziaAdd(event) {
  event.preventDefault();
  clearError($("amneziaError"));
  const client = $("amneziaAddClient").value.trim(), address = $("amneziaAddAddress").value.trim();
  const endpoint_host = $("amneziaAddEndpoint").value.trim(), route = $("amneziaAddRoute").value;
  if (!amneziaValidClient(client) || !/^[0-9.]{7,15}$/.test(address) ||
      !/^[A-Za-z0-9.:-]{1,253}$/.test(endpoint_host) || !["split", "full"].includes(route)) {
    showError($("amneziaError"), "Проверьте имя клиента, IPv4-адрес, адрес сервера и маршрут.");
    return;
  }
  void amneziaPrepareSealed("add-profile", { client, address, endpoint_host, route });
}

function amneziaExport(event) {
  event.preventDefault();
  clearError($("amneziaError"));
  const client = $("amneziaExportClient").value.trim();
  if (!amneziaValidClient(client)) { showError($("amneziaError"), "Проверьте имя клиента."); return; }
  void amneziaPrepareSealed("sealed-export", { client });
}

function amneziaRevoke(event) {
  event.preventDefault();
  clearError($("amneziaError"));
  const client = $("amneziaRevokeClient").value.trim();
  if (!amneziaValidClient(client)) { showError($("amneziaError"), "Проверьте имя клиента."); return; }
  amneziaOpenConfirmation({ action: "revoke", target: amneziaClient.target, client });
}

async function amneziaQueue(payload, pending = null) {
  const serverId = amneziaClient.serverId, generation = amneziaClient.generation;
  const token = state.token, base = state.base;
  const key = pending?.key || crypto.randomUUID();
  const planReview = pending?.kind === "plan";
  const intentReview = pending?.kind === "intent";
  const inlineReview = planReview || intentReview;
  if (!serverId || String(serverId) !== String(state.vpnTargetId) || !vpnTargetReady() || amneziaClient.submittingKey ||
      payload.target !== amneziaClient.target ||
      ["pending", "decrypting"].includes(amneziaClient.profile?.status) ||
      (amneziaClient.jobId && !AMNEZIA_TERMINAL_STATES.has(amneziaClient.job?.state)) ||
      !["status", "settings-preview", "settings-plan", "settings-intent", "settings-apply",
        "add-profile", "sealed-export", "revoke"].includes(payload.action) ||
      (payload.action === "settings-plan" && (!planReview || pending !== amneziaClient.planPending ||
        pending.preview !== amneziaClient.settingsPreview || pending.target !== amneziaClient.target ||
        pending.serverId !== serverId || pending.token !== token || pending.base !== base || !amneziaCanPlan())) ||
      (payload.action === "settings-intent" && (!intentReview || pending !== amneziaClient.intentPending ||
        pending.plan !== amneziaClient.settingsPlan || pending.preview !== amneziaClient.settingsPreview ||
        pending.serverId !== serverId || pending.token !== token || pending.base !== base ||
        !amneziaCanApplyPlan())) ||
      (payload.action === "settings-apply" && (pending?.kind !== "settings-apply" ||
        pending.plan !== amneziaClient.settingsPlan || pending.preview !== amneziaClient.settingsPreview ||
        !amneziaCanApplyPlan() || pending.intent?.confirmation_id !== payload.confirmation_id)) ||
      (payload.action !== "status" && !amneziaCanMutate())) return;
  amneziaClient.submittingKey = key;
  if (pending && !inlineReview) { $("amneziaDialogConfirm").disabled = true; $("amneziaDialogCancel").disabled = true; }
  renderAmneziaControl();
  try {
    const reply = await request(`/api/v1/servers/${encodeURIComponent(serverId)}/amnezia/actions`, {
      method: "POST", headers: { "Idempotency-Key": key }, body: JSON.stringify(payload), timeoutMs: 16000,
    });
    if (!amneziaCurrent(generation, serverId, token, base) || amneziaClient.submittingKey !== key) return;
    if (!reply?.job?.id || String(reply.job.server_id) !== String(serverId)) {
      throw new Error("Hub не вернул ID задания. Проверьте историю перед повтором.");
    }
    amneziaClient.jobId = reply.job.id;
    amneziaClient.job = payload.action === "settings-intent"
      ? { ...reply.job, output: "" } : reply.job;
    amneziaClient.jobAction = payload.action;
    if (planReview) {
      amneziaClient.planRequest = { preview: pending.preview, patch: pending.patch };
      amneziaClient.planPending = null;
      amneziaClient.settingsPlan = null;
      amneziaClient.settingsPlanError = null;
      clearError($("amneziaPlanError"));
    } else if (intentReview) {
      amneziaClient.intentRequest = { plan: pending.plan, preview: pending.preview,
        patch: pending.patch };
      amneziaClient.intentPending = null;
      clearError($("amneziaPlanError"));
    } else {
      if (pending?.kind === "settings-apply" && amneziaClient.intentExpiryTimer !== null) {
        clearTimeout(amneziaClient.intentExpiryTimer);
        amneziaClient.intentExpiryTimer = null;
      }
      amneziaClient.applyRequest = pending?.kind === "settings-apply"
        ? { plan: pending.plan, preview: pending.preview, patch: pending.patch } : null;
      amneziaClient.settingsPreview = null;
      amneziaClient.settingsPreviewError = null;
      amneziaClient.settingsPlan = null;
      amneziaClient.settingsPlanError = null;
      amneziaClient.planPending = null;
      amneziaClient.planRequest = null;
      amneziaClient.intentPending = null;
      amneziaClient.intentRequest = null;
      clearError($("amneziaPlanError"));
    }
    amneziaClient.profile = pending?.privateKey ? {
      jobId: reply.job.id, privateKey: pending.privateKey, client: payload.client,
      action: payload.action, target: payload.target, status: "pending", file: null,
      generation, serverId, token, base,
    } : amneziaClient.profile;
    if (!inlineReview) amneziaClient.pending = null;
    if (pending && !inlineReview) $("amneziaDialog").close();
    clearError($("amneziaError"));
    renderAmneziaControl();
    void amneziaPollJob();
  } catch (error) {
    if (!amneziaCurrent(generation, serverId, token, base) || amneziaClient.submittingKey !== key) return;
    if (pending?.kind === "settings-apply") {
      if (amneziaClient.intentExpiryTimer !== null) clearTimeout(amneziaClient.intentExpiryTimer);
      amneziaClient.intentExpiryTimer = null;
      amneziaClient.pending = null;
      amneziaClient.intentRequest = null;
      amneziaClient.settingsPlan = null;
      amneziaClient.planRequest = null;
      amneziaClient.applyExpectation = null;
      amneziaClient.settingsApplyOutcome = "uncertain";
      $("amneziaDialog").close();
      showError($("amneziaError"),
        "Состояние изменения неизвестно. Обновите состояние брокера и снимок настроек; не повторяйте применение вслепую.");
      return;
    }
    const uncertain = error.status === undefined;
    const message = uncertain
      ? (planReview ? "Ответ потерян. План мог попасть в очередь; повторите запрос с тем же ключом или обновите снимок сервера." :
        intentReview ? "Ответ потерян. Запрос подтверждения мог попасть в очередь; повторите с тем же ключом." :
        "Ответ потерян. Операция могла попасть в очередь; повторите с тем же ключом в этом окне и проверьте историю заданий.")
      : error.message || "Не удалось поставить операцию в очередь.";
    if (planReview) {
      if (!uncertain) amneziaClient.planPending = null;
      showError($("amneziaPlanError"), message);
    } else if (intentReview) {
      if (!uncertain) amneziaClient.intentPending = null;
      showError($("amneziaPlanError"), message);
    } else showError(pending ? $("amneziaDialogError") : $("amneziaError"), message);
  } finally {
    if (amneziaClient.submittingKey === key) {
      amneziaClient.submittingKey = null;
      if (!inlineReview) {
        $("amneziaDialogCancel").disabled = false;
        $("amneziaDialogConfirm").disabled = Boolean(pending?.payload.action === "revoke" &&
          $("amneziaRevokeName").value !== pending.payload.client);
      }
      renderAmneziaControl();
    }
  }
}

async function amneziaConfirm() {
  const pending = amneziaClient.pending;
  if (pending?.kind === "settings-apply" &&
      (!Number.isSafeInteger(pending.receivedAt) || Date.now() - pending.receivedAt >= 240000)) {
    $("amneziaDialog").close();
    showError($("amneziaPlanError"), "Подтверждение истекло. Сверьте снимок и запросите новое.");
    return;
  }
  if (!pending || pending.token !== state.token || pending.base !== state.base ||
      String(pending.serverId) !== String(amneziaClient.serverId) ||
      String(pending.serverId) !== String(state.vpnTargetId) ||
      pending.payload.target !== amneziaClient.target ||
      (pending.kind === "settings-apply" &&
        (pending.plan !== amneziaClient.settingsPlan ||
         pending.preview !== amneziaClient.settingsPreview ||
         pending.payload.confirmation_id !== pending.intent?.confirmation_id ||
         !amneziaCanApplyPlan())) ||
      (pending.payload.action === "revoke" && $("amneziaRevokeName").value !== pending.payload.client)) {
    showError($("amneziaDialogError"), "Сервер или подтверждение изменились. Подготовьте операцию заново.");
    return;
  }
  await amneziaQueue(pending.payload, pending);
}

async function amneziaPrepareSettingsApply() {
  if (!amneziaCanApplyPlan() || amneziaClient.submittingKey || amneziaClient.preparing ||
      (amneziaClient.jobId && !AMNEZIA_TERMINAL_STATES.has(amneziaClient.job?.state))) return;
  clearError($("amneziaPlanError"));
  if (amneziaClient.intentPending) {
    await amneziaQueue(amneziaClient.intentPending.payload, amneziaClient.intentPending);
    return;
  }
  const plan = amneziaClient.settingsPlan, preview = amneziaClient.settingsPreview;
  const patch = { ...amneziaClient.planRequest.patch };
  const payload = { action: "settings-intent", target: "awg2",
    expected_config_sha256: plan.config_sha256,
    expected_generation: plan.generation,
    expected_proposed_config_sha256: plan.proposed_config_sha256,
    parameters: patch };
  amneziaClient.intentPending = { kind: "intent", payload, key: crypto.randomUUID(),
    plan, preview, patch, serverId: amneziaClient.serverId, token: state.token, base: state.base };
  renderAmneziaControl();
  await amneziaQueue(payload, amneziaClient.intentPending);
}

async function amneziaCheck() {
  clearError($("amneziaError"));
  await amneziaQueue({ action: "status", target: amneziaClient.target });
}

async function amneziaSettingsPreview() {
  if (!["uncertain", "refreshing"].includes(amneziaClient.settingsApplyOutcome))
    clearError($("amneziaError"));
  await amneziaQueue({ action: "settings-preview", target: amneziaClient.target });
}

function amneziaPlanProposal(preview) {
  const proposed = {}, patch = {};
  for (const name of AMNEZIA_AWG_FIELDS) {
    const value = $("amneziaPlan" + name).value.trim();
    if (!amneziaValidAwgParameter(name, value, true)) return { error: `Проверьте параметр ${name}: нужно число без ведущих нулей${AMNEZIA_AWG_RANGES.includes(name) ? " или диапазон" : ""}.` };
    proposed[name] = value;
    if (value !== preview.awg_parameters[name]) patch[name] = value;
  }
  if (Number(proposed.Jmin) > Number(proposed.Jmax)) return { error: "Jmin не может быть больше Jmax." };
  if (["S1", "S2", "S3", "S4"].some((name) => Number(proposed[name]) < 12))
    return { error: "S1–S4 должны быть не меньше 12." };
  if (!Object.keys(patch).length) return { error: "Измените хотя бы один параметр для расчёта плана." };
  return { patch };
}

async function amneziaPlanSubmit(event) {
  event.preventDefault();
  if (!amneziaCanPlan() || amneziaClient.submittingKey || amneziaClient.preparing ||
      ["pending", "decrypting"].includes(amneziaClient.profile?.status) ||
      (amneziaClient.jobId && !AMNEZIA_TERMINAL_STATES.has(amneziaClient.job?.state))) return;
  clearError($("amneziaPlanError"));
  if (amneziaClient.planPending) {
    await amneziaQueue(amneziaClient.planPending.payload, amneziaClient.planPending);
    return;
  }
  const preview = amneziaClient.settingsPreview;
  const proposal = amneziaPlanProposal(preview);
  if (proposal.error) { showError($("amneziaPlanError"), proposal.error); return; }
  const payload = { action: "settings-plan", target: "awg2",
    expected_config_sha256: preview.config_sha256,
    expected_generation: preview.generation, parameters: proposal.patch };
  amneziaClient.planPending = { kind: "plan", payload, patch: proposal.patch,
    key: crypto.randomUUID(), preview, target: amneziaClient.target,
    serverId: amneziaClient.serverId, token: state.token, base: state.base };
  amneziaClient.settingsPlan = null;
  amneziaClient.settingsPlanError = null;
  renderAmneziaControl();
  await amneziaQueue(payload, amneziaClient.planPending);
}

function amneziaPlanReset() {
  if (!amneziaCanPlan() || amneziaClient.submittingKey || amneziaClient.preparing ||
      ["pending", "decrypting"].includes(amneziaClient.profile?.status) ||
      (amneziaClient.jobId && !AMNEZIA_TERMINAL_STATES.has(amneziaClient.job?.state))) return;
  amneziaClient.planPending = null;
  amneziaClient.planRequest = null;
  amneziaClient.intentPending = null;
  amneziaClient.intentRequest = null;
  amneziaClient.settingsPlan = null;
  amneziaClient.settingsPlanError = null;
  amneziaPlanInputsFromPreview(amneziaClient.settingsPreview);
  clearError($("amneziaPlanError"));
  renderAmneziaControl();
}

function amneziaPlanInputChanged() {
  // An uncertain POST retains its exact payload/key; its fields are disabled.
  // A running plan also keeps its snapshot until the result is checked.
  if (amneziaClient.planPending || amneziaClient.submittingKey ||
      (amneziaClient.jobAction === "settings-plan" && amneziaClient.jobId &&
        !AMNEZIA_TERMINAL_STATES.has(amneziaClient.job?.state))) return;
  amneziaClient.settingsPlan = null;
  amneziaClient.settingsPlanError = null;
  amneziaClient.planRequest = null;
  amneziaClient.intentPending = null;
  amneziaClient.intentRequest = null;
  if (amneziaClient.pending?.kind === "settings-apply" && !amneziaClient.submittingKey)
    $("amneziaDialog").close();
  clearError($("amneziaPlanError"));
  renderAmneziaControl();
}

async function amneziaPrepareProfile(job, profile) {
  if (profile.status !== "pending" || job.state !== "succeeded") return;
  profile.status = "decrypting";
  renderAmneziaJob();
  let bytes;
  try {
    let envelope = job.output;
    if (profile.action === "add-profile") {
      const result = JSON.parse(job.output);
      if (result?.target !== profile.target || result.action !== "added" ||
          result.client !== profile.client || result.profile_format !== AMNEZIA_TARGETS[profile.target]?.format ||
          !result.sealed_profile) throw new Error("Неверный ответ профиля.");
      envelope = JSON.stringify(result.sealed_profile);
    }
    bytes = await decryptSealedProfile(profile.privateKey, envelope, profile.target, profile.client);
    if (!amneziaProfileCurrent(profile) || amneziaClient.jobId !== profile.jobId) return;
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (!text.startsWith("[Interface]\n") || !text.includes("\n[Peer]\n")) throw new Error("Неверный формат профиля.");
    profile.file = new File([bytes], `amnezia-${profile.target}-${profile.client}.conf`, { type: "text/plain" });
    profile.privateKey = null;
    profile.status = "ready";
  } catch {
    if (amneziaProfileCurrent(profile)) {
      profile.privateKey = null;
      profile.status = "failed";
    }
  } finally {
    bytes?.fill(0);
    if (amneziaProfileCurrent(profile)) renderAmneziaJob();
  }
}

async function amneziaPollJob() {
  if (!amneziaClient.jobId || amneziaClient.polling === amneziaClient.jobId) return;
  const generation = amneziaClient.generation, serverId = amneziaClient.serverId;
  const token = state.token, base = state.base, jobId = amneziaClient.jobId;
  amneziaClient.polling = jobId;
  const current = () => amneziaCurrent(generation, serverId, token, base) && amneziaClient.jobId === jobId;
  const deadline = Date.now() + 130000;
  try {
    while (current() && Date.now() < deadline) {
      const reply = await request(`/api/v1/jobs/${encodeURIComponent(jobId)}`, { timeoutMs: 12000 });
      if (!current()) return;
      if (!reply?.job || reply.job.id !== jobId || String(reply.job.server_id) !== String(serverId)) {
        throw new Error("Hub вернул неверное задание.");
      }
      // The one-time confirmation handle may be inside a completed intent
      // job. Keep it only in the pending in-memory dialog, never in job state.
      amneziaClient.job = amneziaClient.jobAction === "settings-intent"
        ? { ...reply.job, output: "" } : reply.job;
      if (AMNEZIA_TERMINAL_STATES.has(reply.job.state)) {
        const finishedAction = amneziaClient.jobAction;
        let refreshSettings = false;
        if (amneziaClient.jobAction === "settings-preview") {
          amneziaClient.settingsPreview = reply.job.state === "succeeded" && reply.job.exit_code === 0
            ? amneziaParseSettingsPreview(reply.job.output, amneziaClient.target) : null;
          amneziaClient.settingsPreviewError = amneziaClient.settingsPreview ? null :
            "Настройки не получены. Проверьте, что контейнер зарегистрирован и его состояние не изменилось.";
          if (amneziaClient.applyExpectation) {
            const expectation = amneziaClient.applyExpectation;
            amneziaClient.settingsApplyOutcome = amneziaClient.settingsPreview?.config_sha256 === expectation.configSha &&
              amneziaClient.settingsPreview?.generation === expectation.generation ? "applied" : "uncertain";
            amneziaClient.applyExpectation = null;
            if (amneziaClient.settingsApplyOutcome === "uncertain") showError($("amneziaError"),
              "Состояние изменения неизвестно: свежий снимок не подтвердил результат применения. Проверьте брокер и настройки.");
          }
          amneziaPlanInputsFromPreview(amneziaClient.settingsPreview);
        } else if (amneziaClient.jobAction === "settings-plan") {
          const request = amneziaClient.planRequest;
          amneziaClient.settingsPlan = reply.job.state === "succeeded" && reply.job.exit_code === 0 &&
            request?.preview === amneziaClient.settingsPreview
            ? amneziaParseSettingsPlan(reply.job.output, request.preview, request.patch) : null;
          amneziaClient.settingsPlanError = amneziaClient.settingsPlan ? null :
            "План не получен или ответ не прошёл проверку. Обновите снимок настроек и попробуйте снова.";
          if (amneziaClient.settingsPlanError) showError($("amneziaPlanError"), amneziaClient.settingsPlanError);
          else clearError($("amneziaPlanError"));
        } else if (finishedAction === "settings-intent") {
          const request = amneziaClient.intentRequest;
          const intent = reply.job.state === "succeeded" && reply.job.exit_code === 0 &&
            request?.plan === amneziaClient.settingsPlan &&
            request?.preview === amneziaClient.settingsPreview
            ? amneziaParseSettingsIntent(reply.job.output, request.plan) : null;
          amneziaClient.intentRequest = null;
          if (!intent || !amneziaOpenSettingsConfirmation(intent, request)) {
            const message = reply.job.state === "succeeded"
              ? "Подтверждение не прошло проверку. Обновите снимок сервера и план."
              : "Подтверждение не получено. Проверьте отдельное разрешение «Изменение AWG3» в Connect и состояние брокера.";
            showError($("amneziaPlanError"), message);
          } else clearError($("amneziaPlanError"));
        } else if (finishedAction === "settings-apply") {
          const result = reply.job.state === "succeeded" && reply.job.exit_code === 0
            ? amneziaParseSettingsApplied(reply.job.output, amneziaClient.applyRequest) : null;
          amneziaClient.settingsApplyOutcome = result ? "refreshing" : "uncertain";
          amneziaClient.applyExpectation = result
            ? { configSha: result.config_sha256, generation: result.generation } : null;
          amneziaClient.applyRequest = null;
          refreshSettings = true;
          if (!result) showError($("amneziaError"),
            "Итог изменения настроек не подтверждён. Проверяем свежий снимок; не повторяйте применение вслепую.");
        }
        renderAmneziaControl();
        if (reply.job.state === "succeeded" && amneziaClient.profile?.jobId === jobId) {
          await amneziaPrepareProfile(reply.job, amneziaClient.profile);
        }
        if (reply.job.state === "succeeded" && amneziaClient.profile?.status === "ready") {
          try {
            const result = JSON.parse(reply.job.output);
            if (result?.target === amneziaClient.profile.target && result.action === "revoked" &&
                result.client === amneziaClient.profile.client) amneziaClient.profile = null;
          } catch { /* A successful status result need not be a revoke result. */ }
        }
        if (current()) await amneziaLoadControl();
        if (current() && refreshSettings) {
          await amneziaSettingsPreview();
          if (current() && amneziaClient.applyExpectation) {
            amneziaClient.applyExpectation = null;
            amneziaClient.settingsApplyOutcome = "uncertain";
            showError($("amneziaError"),
              "Состояние изменения неизвестно: не удалось обновить снимок сервера. Проверьте брокер и настройки.");
            renderAmneziaControl();
          }
        }
        return;
      }
      renderAmneziaControl();
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }
    if (current() && ["settings-apply", "settings-preview"].includes(amneziaClient.jobAction) &&
        (amneziaClient.jobAction === "settings-apply" || amneziaClient.applyExpectation)) {
      amneziaClient.applyExpectation = null;
      amneziaClient.settingsApplyOutcome = "uncertain";
      showError($("amneziaError"),
        "Состояние изменения неизвестно: ожидание результата истекло. Обновите страницу и проверьте состояние брокера и настроек.");
      renderAmneziaControl();
    }
  } catch (error) {
    if (current()) {
      if (amneziaClient.jobAction === "settings-apply" || amneziaClient.applyExpectation) {
        amneziaClient.applyExpectation = null;
        amneziaClient.settingsApplyOutcome = "uncertain";
        showError($("amneziaError"),
          "Состояние изменения неизвестно: результат не получен. Обновите страницу и проверьте состояние брокера и настроек.");
        renderAmneziaControl();
      } else showError($("amneziaError"), error.message || "Не удалось узнать состояние задания.");
    }
  } finally {
    if (amneziaClient.polling === jobId) amneziaClient.polling = null;
  }
}

async function amneziaDownload() {
  const profile = amneziaClient.profile;
  if (!profile || !amneziaProfileCurrent(profile) || profile.status !== "ready" || !profile.file) return;
  const bridge = nativeProfileBridge();
  if (bridge) {
    if (profile.nativeSaving) return;
    profile.nativeSaving = true;
    let bytes;
    try {
      const filename = `amnezia-${profile.target}-${profile.client}.conf`;
      if (!amneziaValidClient(profile.client) || profile.file.name !== filename ||
          !Number.isSafeInteger(profile.file.size) || profile.file.size < 1 || profile.file.size > 16384) {
        throw new Error("Неверный профиль.");
      }
      bytes = new Uint8Array(await profile.file.arrayBuffer());
      if (!amneziaProfileCurrent(profile) || bytes.length !== profile.file.size) return;
      bridge.postMessage(JSON.stringify({ version: 1, filename, data: base64UrlEncode(bytes) }));
      $("amneziaProfileStatus").textContent = "Запрос на сохранение передан приложению. Выберите место для файла .conf.";
    } catch {
      if (amneziaClient.profile === profile) $("amneziaProfileStatus").textContent = "Не удалось сохранить профиль в приложении.";
    } finally { bytes?.fill(0); profile.nativeSaving = false; }
    return;
  }
  const url = URL.createObjectURL(profile.file);
  amneziaClient.downloadUrls.add(url);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = profile.file.name;
  anchor.hidden = true;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => {
    if (amneziaClient.downloadUrls.delete(url)) URL.revokeObjectURL(url);
  }, 60000);
}

async function amneziaShare() {
  const profile = amneziaClient.profile;
  if (!profile || !amneziaProfileCurrent(profile) || profile.status !== "ready" || !profile.file) return;
  try {
    if (navigator.canShare?.({ files: [profile.file] })) {
      await navigator.share({ files: [profile.file], title: `Профиль ${AMNEZIA_TARGETS[profile.target].label}` });
    }
  } catch (error) {
    if (error?.name !== "AbortError" && amneziaClient.profile === profile) {
      $("amneziaProfileStatus").textContent = "Не удалось поделиться профилем. Используйте «Скачать .conf».";
    }
  }
}

$("amneziaCheck").addEventListener("click", amneziaCheck);
$("amneziaSettingsPreview").addEventListener("click", amneziaSettingsPreview);
$("amneziaPlanForm").addEventListener("submit", amneziaPlanSubmit);
$("amneziaPlanReset").addEventListener("click", amneziaPlanReset);
$("amneziaPlanPrepareApply").addEventListener("click", () => { void amneziaPrepareSettingsApply(); });
for (const name of AMNEZIA_AWG_FIELDS) $("amneziaPlan" + name).addEventListener("input", amneziaPlanInputChanged);
$("amneziaTarget").addEventListener("change", amneziaTargetChanged);
$("amneziaAddForm").addEventListener("submit", amneziaAdd);
$("amneziaExportForm").addEventListener("submit", amneziaExport);
$("amneziaRevokeForm").addEventListener("submit", amneziaRevoke);
$("amneziaDialogConfirm").addEventListener("click", amneziaConfirm);
$("amneziaDialogCancel").addEventListener("click", () => { if (!amneziaClient.submittingKey) $("amneziaDialog").close(); });
$("amneziaDialog").addEventListener("cancel", (event) => { if (amneziaClient.submittingKey) event.preventDefault(); });
$("amneziaDialog").addEventListener("close", () => {
  if (!amneziaClient.submittingKey) {
    if (amneziaClient.intentExpiryTimer !== null) clearTimeout(amneziaClient.intentExpiryTimer);
    amneziaClient.intentExpiryTimer = null;
    amneziaClient.pending = null;
    amneziaClient.intentRequest = null;
  }
  $("amneziaRevokeName").value = "";
  $("amneziaDialogConfirm").textContent = "Выполнить";
  renderAmneziaControl();
});
$("amneziaRevokeName").addEventListener("input", () => {
  $("amneziaDialogConfirm").disabled = amneziaClient.pending?.payload.action === "revoke" &&
    $("amneziaRevokeName").value !== amneziaClient.pending.payload.client;
});
$("amneziaDownload").addEventListener("click", amneziaDownload);
$("amneziaShare").addEventListener("click", amneziaShare);
setInterval(() => {
  if (state.token && state.view === "vpn" && !document.hidden) {
    void amneziaLoadControl();
    if (amneziaClient.jobId && !AMNEZIA_TERMINAL_STATES.has(amneziaClient.job?.state)) void amneziaPollJob();
  }
}, 15000);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && state.token && state.view === "vpn") {
    void amneziaLoadControl();
    if (amneziaClient.jobId && !AMNEZIA_TERMINAL_STATES.has(amneziaClient.job?.state)) void amneziaPollJob();
  }
});

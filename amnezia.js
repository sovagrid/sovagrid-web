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
const amneziaSetup = { generation: 0, busy: false, fingerprint: null, changedPin: false,
  controller: null, endpoint: null, setup: null, enrollment: null, identity: null,
  source: null, sourceIdentity: null, pendingAction: null };
const wgControl = { preview: null, identity: null, pendingAction: null };
const AMNEZIA_ENROLL_FIELDS = ["protocol", "action", "writes", "target", "container_id", "image_id",
  "config_sha256", "table_sha256", "configured_clients", "vpn_protocol", "interface", "listen_port",
  "server_subnet", "host_key_fingerprint", "reverify_required"].sort();
const AMNEZIA_REMOTE_FIELDS = ["scope", "host", "port"];
const AMNEZIA_SETUP_CONFIRM = { enroll: "ENROLL_EXISTING_CONTAINER", install: "INSTALL_AMNEZIA_BROKER",
  awg2: "I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_AWG2",
  wireguard: "I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_WIREGUARD" };
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
  amneziaSetupReset();
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
  amneziaSetupRender();
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
            `Локальный брокер ${label} выключен или ещё не проверен. Для хоста панели или другого SSH-доступного Ubuntu-сервера используйте мастер выше. Для маршрута через промежуточный хост используйте SovaGrid Connect.`;
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

// This setup preview is separate from Agent commands. The gateway requires
// unrestricted Hub admin access for both the Hub and an entered SSH target.
function amneziaSetupAllowed() {
  if (!state.token || !state.user || state.view !== "vpn" || !hubCanGlobalAdmin()) return false;
  try {
    const page = new URL(location.href);
    const hub = new URL(state.base, page);
    const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(page.hostname);
    return hub.origin === page.origin && (page.protocol === "https:" || (page.protocol === "http:" && loopback));
  } catch { return false; }
}

function amneziaSetupRemote() { return $("amneziaSetupScopeRemote").checked; }
function amneziaSetupEndpoint() {
  if (!amneziaSetupRemote()) return null;
  const host = $("amneziaSetupRemoteHost").value.trim().toLowerCase();
  const rawPort = $("amneziaSetupRemotePort").value;
  if (!host || host.length > 253 || !/^[A-Za-z0-9.:-]+$/.test(host) || host.includes("..") ||
      !/^[0-9]{1,5}$/.test(rawPort)) throw new Error("INVALID_TARGET");
  const port = Number(rawPort);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("INVALID_TARGET");
  return { host, port };
}
function amneziaSetupSameEndpoint() {
  if (!amneziaSetupRemote()) return amneziaSetup.endpoint === null;
  try {
    const target = amneziaSetupEndpoint();
    return amneziaSetup.endpoint?.host === target.host && amneziaSetup.endpoint?.port === target.port;
  } catch { return false; }
}
function amneziaSetupPinName() {
  if (!amneziaSetupRemote() || !amneziaSetup.endpoint) return `sovagrid.ssh-host-key:${location.origin}`;
  const { host, port } = amneziaSetup.endpoint;
  // Share the same public host-key pin as the Add Server wizard.
  return `sovagrid.target-ssh-host-key:${location.origin}:${host}:${port}`;
}
function amneziaSetupPin() {
  try { return localStorage.getItem(amneziaSetupPinName()); } catch { return null; }
}
function amneziaSetupSavePin(fingerprint) {
  try { localStorage.setItem(amneziaSetupPinName(), fingerprint); }
  catch { /* Private browsing may disable storage. */ }
}
function amneziaSetupClearSecrets() {
  for (const id of ["amneziaSetupPassword", "amneziaSetupPrivateKey", "amneziaSetupPassphrase"]) $(id).value = "";
}
function amneziaSetupPendingKey() {
  if (!amneziaSetupRemote()) return `sovagrid.amnezia-setup-pending:${location.origin}`;
  let endpoint = amneziaSetup.endpoint;
  if (!endpoint) {
    try { endpoint = amneziaSetupEndpoint(); } catch { /* No target chosen yet. */ }
  }
  return `sovagrid.amnezia-setup-pending:${location.origin}:${endpoint
    ? `${endpoint.host}:${endpoint.port}` : "unselected_target"}`;
}
function amneziaSetupPending() {
  try { return sessionStorage.getItem(amneziaSetupPendingKey()) === "1"; } catch { return false; }
}
function amneziaSetupMarkPending(pending) {
  try {
    if (pending) sessionStorage.setItem(amneziaSetupPendingKey(), "1");
    else sessionStorage.removeItem(amneziaSetupPendingKey());
  } catch { /* Private browsing may disable storage. */ }
}
function amneziaSetupIdentity() {
  const endpoint = amneziaSetupRemote() ? amneziaSetupEndpoint() : null;
  return { target: $("amneziaSetupTarget").value, username: $("amneziaSetupUsername").value.trim(),
    method: $("amneziaSetupAuthKey").checked ? "private_key" : "password",
    fingerprint: amneziaSetup.fingerprint, scope: endpoint ? "entered_target" : "hub_host",
    host: endpoint?.host ?? null, port: endpoint?.port ?? null };
}
function amneziaSetupSameIdentity() {
  try {
    const current = amneziaSetupIdentity(), reviewed = amneziaSetup.identity;
    return reviewed && Object.keys(current).every((key) => current[key] === reviewed[key]);
  } catch { return false; }
}
function amneziaSourceSameIdentity() {
  try {
    const current = amneziaSetupIdentity(), reviewed = amneziaSetup.sourceIdentity;
    return reviewed && Object.keys(current).every((key) => current[key] === reviewed[key]);
  } catch { return false; }
}
function amneziaSetupDiscardSource() {
  amneziaSetup.source = null;
  amneziaSetup.sourceIdentity = null;
  $("amneziaSourceReview").hidden = true;
  $("amneziaSourceSummary").textContent = "";
  $("amneziaSourceDigest").textContent = "";
  $("amneziaSourceNotice").textContent = "";
  wgControlReset();
}
function amneziaSetupDiscardReview() {
  amneziaSetup.setup = null;
  amneziaSetup.enrollment = null;
  amneziaSetup.identity = null;
  $("amneziaSetupResult").hidden = true;
  $("amneziaSetupEnrollment").hidden = true;
}
function amneziaSetupShowStatus(result) {
  if (!amneziaSetupValidResult(result, $("amneziaSetupTarget").value)) throw new Error("INVALID_RESPONSE");
  amneziaSetup.setup = result;
  amneziaSetup.enrollment = null;
  amneziaSetup.identity = amneziaSetupIdentity();
  $("amneziaSetupEnrollment").hidden = true;
  $("amneziaSetupSummary").textContent = result.marker === "unsafe" || result.other_marker === "unsafe"
    ? "Найдены конфликтующие или небезопасные данные подключения. Изменений не выполнено."
    : result.enrolled
      ? `Брокер ${result.target === "awg2" ? "AmneziaWG" : "WireGuard"} подключён. Клиентов: ${result.configured_clients}, из них добавлены SovaGrid: ${result.owned_clients}.`
      : "Брокер ещё не подключён. Можно проверить существующий VPN-контейнер на этом хосте. Изменений не выполнено.";
  $("amneziaSetupDetails").textContent = `Служба: ${result.service_active ? "работает" : "не запущена"}. Сокет: ${result.socket_active ? "работает" : "не запущен"}. Установщик: ${result.installer_ready ? "готов" : "недоступен"}.`;
  $("amneziaSetupNext").textContent = "Для каждого следующего шага снова введите пароль или выберите ключ SSH. Данные входа не сохраняются.";
  $("amneziaSetupResult").hidden = false;
  amneziaSetupRender();
}
function amneziaSetupRender() {
  $("amneziaSetupHost").textContent = location.hostname || "этот хост";
  const remote = amneziaSetupRemote();
  $("amneziaSetupRemoteFields").hidden = !remote;
  const allowed = amneziaSetupAllowed();
  $("amneziaSetupAvailability").textContent = !state.user ? "Войдите как администратор этого Hub." :
    !hubCanGlobalAdmin() ? "Для проверки нужен администратор со свободным доступом ко всем серверам Hub." :
      !allowed ? "Откройте этот Hub по HTTPS или через локальный SSH-туннель и войдите в него напрямую." :
        amneziaSetupPending() ? "Предыдущее действие могло продолжиться после потери связи. Проверьте состояние заново перед следующим шагом." :
          remote ? "Сначала проверьте SSH-ключ удалённого сервера, затем войдите в него. Пароль и файл ключа не сохраняются." :
            "Сначала проверьте SSH-ключ хоста панели, затем выберите способ входа. Пароль и файл ключа не сохраняются.";
  $("amneziaSetupInspect").disabled = !allowed || amneziaSetup.busy;
  $("amneziaSetupSubmit").disabled = !allowed || amneziaSetup.busy || !amneziaSetup.fingerprint ||
    amneziaSetup.changedPin || !$("amneziaSetupTrust").checked || !amneziaSetupSameEndpoint();
  const sourceSafe = remote && allowed && !amneziaSetup.busy && !!amneziaSetup.fingerprint &&
    !amneziaSetup.changedPin && $("amneziaSetupTrust").checked && amneziaSetupSameEndpoint();
  $("amneziaSourcePreview").disabled = !sourceSafe;
  $("amneziaSourceReview").hidden = !sourceSafe || !amneziaSourceSameIdentity() || !amneziaSetup.source;
  $("amneziaSourceApply").hidden = !amneziaSetup.source || !sourceSafe ||
    !amneziaSourceSameIdentity() || amneziaSetup.source.cleanup_required ||
    amneziaSetup.source.change === "current";
  $("amneziaSourceRecover").hidden = !amneziaSetup.source || !sourceSafe ||
    !amneziaSourceSameIdentity() || !amneziaSetup.source.cleanup_required;
  for (const id of ["amneziaSetupTarget", "amneziaSetupScopeLocal", "amneziaSetupScopeRemote",
    "amneziaSetupRemoteHost", "amneziaSetupRemotePort", "amneziaSetupUsername", "amneziaSetupAuthPassword",
    "amneziaSetupAuthKey", "amneziaSetupPassword", "amneziaSetupPrivateKey", "amneziaSetupPassphrase",
    "amneziaSetupTrust"]) $(id).disabled = amneziaSetup.busy;
  const setup = amneziaSetup.setup, exact = amneziaSetupSameIdentity();
  const safe = allowed && exact && !amneziaSetup.busy && !amneziaSetup.changedPin &&
    $("amneziaSetupTrust").checked && amneziaSetupSameEndpoint() &&
    setup?.marker !== "unsafe" && setup?.other_marker !== "unsafe";
  $("amneziaSetupEnrollPreview").hidden = !safe || setup?.enrolled !== false;
  $("amneziaSetupInstall").hidden = !safe || setup?.enrolled !== true || !setup?.installer_ready ||
    setup?.installed_current || setup?.marker !== "absent" || setup?.other_marker !== "absent" ||
    setup?.socket_active || setup?.service_active;
  $("amneziaSetupArm").hidden = !safe || setup?.enrolled !== true || !setup?.installed_current ||
    !setup?.can_arm || setup?.marker !== "absent";
  $("amneziaSetupEnroll").disabled = !safe || !amneziaSetup.enrollment || amneziaSetup.busy;
  wgControlRender();
}
function amneziaSetupReset() {
  amneziaSetup.generation++;
  amneziaSetup.controller?.abort();
  amneziaSetup.controller = null;
  amneziaSetup.busy = false;
  amneziaSetup.fingerprint = null;
  amneziaSetup.changedPin = false;
  amneziaSetup.endpoint = null;
  amneziaSetup.pendingAction = null;
  if ($("amneziaSetupDialog").open) $("amneziaSetupDialog").close();
  $("amneziaSetupMaintenance").checked = false;
  $("amneziaSetupTrust").checked = false;
  $("amneziaSetupHostKeyReview").hidden = true;
  $("amneziaSetupReplaceKey").hidden = true;
  amneziaSetupDiscardReview();
  amneziaSetupDiscardSource();
  $("amneziaSetupSummary").textContent = "";
  $("amneziaSetupDetails").textContent = "";
  $("amneziaSetupUsername").value = "";
  amneziaSetupClearSecrets();
  clearError($("amneziaSetupError"));
  amneziaSetupRender();
}
function amneziaSetupMethodChanged() {
  const key = $("amneziaSetupAuthKey").checked;
  $("amneziaSetupKeyFields").hidden = !key;
  $("amneziaSetupPasswordFields").hidden = key;
  amneziaSetupClearSecrets();
  amneziaSetupDiscardReview();
  amneziaSetupDiscardSource();
  amneziaSetupRender();
}
function amneziaSetupCurrent(generation, token, base, origin) {
  return amneziaSetup.generation === generation && state.token === token && state.base === base &&
    location.origin === origin && amneziaSetupAllowed();
}
async function amneziaSetupApi(path, value, token, timeoutMs) {
  const controller = new AbortController();
  amneziaSetup.controller = controller;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(path, { method: "POST", credentials: "omit", cache: "no-store",
      redirect: "error", referrerPolicy: "no-referrer",
      headers: { "Content-Type": "application/json", Accept: "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(value), signal: controller.signal });
    let payload;
    try { payload = await response.json(); } catch { throw new Error("INVALID_RESPONSE"); }
    if (!response.ok) {
      const failure = new Error(typeof payload?.error === "string" ? payload.error : "SSH_UNAVAILABLE");
      failure.status = response.status;
      throw failure;
    }
    return payload;
  } catch (failure) {
    if (failure.name === "AbortError") throw new Error("SSH_TIMEOUT");
    throw failure;
  } finally {
    clearTimeout(timer);
    if (amneziaSetup.controller === controller) amneziaSetup.controller = null;
  }
}
function amneziaSetupExplain(failure) {
  if (failure.status === 404 || failure.status === 502) return "SSH-проверка на этом Hub ещё не включена. Обновите серверный пакет.";
  if (failure.message === "HOST_KEY_CHANGED") return "Ключ SSH-хоста изменился. Сверьте новый отпечаток вне SovaGrid и начните проверку заново.";
  if (failure.message === "AUTH_FAILED") return "SSH не принял имя пользователя, пароль или ключ.";
  if (failure.message === "AUTH_REQUIRED") return "Сеанс Hub завершился. Войдите в панель заново.";
  if (failure.message === "ADMIN_FORBIDDEN") return "Для проверки нужен администратор Hub с полным доступом.";
  if (failure.message === "SETUP_UNAVAILABLE") return "Предпросмотр на этом хосте недоступен. Проверьте серверный пакет и права SSH-пользователя.";
  if (failure.message === "SETUP_CHANGED") return "Состояние контейнера изменилось. Проверьте его заново и повторите действие.";
  if (failure.message === "SETUP_UNCERTAIN") return "Связь прервалась или ответ не подтверждён. Действие могло выполниться: проверьте состояние перед повтором.";
  if (["APPLY_UNCERTAIN", "RECOVERY_UNCERTAIN"].includes(failure.message))
    return "Ответ о подготовке VPN-кода не подтверждён. Состояние могло измениться: сначала проверьте пакет снова и при необходимости завершите очистку, не повторяя действие вслепую.";
  if (failure.message === "RATE_LIMIT") return "Слишком много попыток. Подождите минуту.";
  if (failure.message === "BUSY") return "SSH-шлюз занят. Повторите позже.";
  if (failure.message === "SSH_TIMEOUT") return "SSH-хост не ответил вовремя.";
  if (failure.message === "INVALID_INPUT") return "Проверьте поля SSH и попробуйте снова.";
  if (failure.message === "INVALID_TARGET") return "Укажите корректный адрес и порт SSH удалённого сервера (1–65535).";
  if (failure.message === "TARGET_NOT_READY") return "Удалённый сервер должен быть Ubuntu с установленным SovaGrid Agent или Hub. При необходимости сначала установите Agent через мастер серверов.";
  if (failure.message === "SOURCE_UNTRUSTED" || failure.message === "SOURCE_CHANGED")
    return "Проверенный пакет VPN на Hub изменился или недоступен. Обновите серверную часть и проверьте пакет снова.";
  if (failure.message === "STALE_PREVIEW" || failure.message === "STATE_CONFLICT")
    return "Файлы VPN на сервере изменились после проверки. Проверьте пакет снова перед применением.";
  if (failure.message === "OWNERSHIP_CONFLICT" || failure.message === "CONTROL_ACTIVE")
    return "На сервере есть чужие файлы или работающий брокер управления. SovaGrid не будет их заменять; проверьте сервер и окно обслуживания.";
  if (failure.message === "RECOVERY_REQUIRED" || failure.message === "STAGE_CLEANUP_REQUIRED")
    return "Осталась незавершённая подготовка VPN-кода. Проверьте пакет и завершите очистку перед новым действием.";
  if (failure.message === "ROOT_REQUIRED") return "Для подготовки VPN-кода нужен SSH-вход root или sudo без запроса пароля.";
  if (["JOURNAL_UNAVAILABLE", "UNSAFE_LOCK", "OPERATION_FAILED", "INTERNAL_ERROR",
       "RESPONSE_TOO_LARGE", "RUNTIME_UNAVAILABLE"].includes(failure.message))
    return "Подготовка VPN-кода не завершилась. Проверьте состояние сервера и повторите предпросмотр.";
  return "Не удалось проверить подключение Amnezia на этом хосте.";
}
async function amneziaSetupInspect() {
  if (!amneziaSetupAllowed() || amneziaSetup.busy) return;
  let endpoint;
  try { endpoint = amneziaSetupEndpoint(); }
  catch (failure) { showError($("amneziaSetupError"), amneziaSetupExplain(failure)); return; }
  const generation = ++amneziaSetup.generation, token = state.token, base = state.base, origin = location.origin;
  amneziaSetup.busy = true;
  amneziaSetup.fingerprint = null;
  amneziaSetup.changedPin = false;
  amneziaSetup.endpoint = null;
  $("amneziaSetupTrust").checked = false;
  $("amneziaSetupHostKeyReview").hidden = true;
  $("amneziaSetupReplaceKey").hidden = true;
  amneziaSetupDiscardReview();
  amneziaSetupDiscardSource();
  amneziaSetupClearSecrets();
  clearError($("amneziaSetupError"));
  amneziaSetupRender();
  try {
    const result = await amneziaSetupApi(endpoint ? "/api/v1/browser-ssh/target-host-key" :
      "/api/v1/browser-ssh/host-key", endpoint ?? {}, endpoint ? token : "", 12000);
    if (!amneziaSetupCurrent(generation, token, base, origin)) return;
    if (result?.protocol !== 1 || !Number.isSafeInteger(result.port) || result.port < 1 || result.port > 65535 ||
        typeof result.key_type !== "string" || !/^[A-Za-z0-9@._-]{4,96}$/.test(result.key_type) ||
        typeof result.fingerprint !== "string" || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(result.fingerprint) ||
        (endpoint && (result.scope !== "entered_target" || result.reverify_required !== true ||
          result.host !== endpoint.host || result.port !== endpoint.port))) {
      throw new Error("INVALID_RESPONSE");
    }
    amneziaSetup.endpoint = endpoint;
    if (!amneziaSetupSameEndpoint()) throw new Error("INVALID_RESPONSE");
    amneziaSetup.fingerprint = result.fingerprint;
    $("amneziaSetupKeyHost").textContent = endpoint?.host ?? location.hostname;
    $("amneziaSetupKeyPort").textContent = `:${result.port}`;
    $("amneziaSetupKeyType").textContent = result.key_type;
    $("amneziaSetupFingerprint").textContent = result.fingerprint;
    $("amneziaSetupHostKeyReview").hidden = false;
    const saved = amneziaSetupPin();
    if (saved && saved !== result.fingerprint) {
      amneziaSetup.changedPin = true;
      $("amneziaSetupReplaceKey").hidden = false;
      showError($("amneziaSetupError"), "Закреплённый SSH-ключ изменился. Сверьте новый отпечаток независимо и подтвердите замену.");
    } else if (saved === result.fingerprint) $("amneziaSetupTrust").checked = true;
  } catch (failure) {
    if (amneziaSetupCurrent(generation, token, base, origin)) {
      amneziaSetup.endpoint = null;
      amneziaSetup.fingerprint = null;
      showError($("amneziaSetupError"), amneziaSetupExplain(failure));
    }
  } finally {
    if (amneziaSetup.generation === generation) amneziaSetup.busy = false;
    amneziaSetupRender();
  }
}
function amneziaSetupValidResult(result, target) {
  if (result?.protocol !== 1 || result.target !== target || typeof result.enrolled !== "boolean" ||
      !["absent", "valid", "unsafe"].includes(result.marker) ||
      !["absent", "valid", "unsafe"].includes(result.other_marker) ||
      ["socket_active", "service_active", "installer_ready", "installed_current", "can_arm"]
        .some((key) => typeof result[key] !== "boolean")) return false;
  if (amneziaSetup.endpoint) {
    if (result.scope !== "entered_target" || result.host !== amneziaSetup.endpoint.host ||
        result.port !== amneziaSetup.endpoint.port ||
        result.host_key_fingerprint !== amneziaSetup.fingerprint) return false;
  } else if (["scope", "host", "port", "host_key_fingerprint"]
    .some((key) => Object.hasOwn(result, key))) return false;
  return result.enrolled ? /^[0-9a-f]{64}$/.test(result.container_id) &&
    Number.isSafeInteger(result.configured_clients) && result.configured_clients >= 0 &&
    Number.isSafeInteger(result.owned_clients) && result.owned_clients >= 0 &&
    result.owned_clients <= result.configured_clients : ["NOT_ENROLLED", "UNAVAILABLE"].includes(result.reason);
}
async function amneziaSetupPreview(event) {
  event.preventDefault();
  if (!amneziaSetupAllowed() || amneziaSetup.busy || !amneziaSetup.fingerprint ||
      amneziaSetup.changedPin || !$("amneziaSetupTrust").checked ||
      !amneziaSetupSameEndpoint()) return;
  const fingerprint = amneziaSetup.fingerprint, previousPin = amneziaSetupPin();
  const endpoint = amneziaSetup.endpoint;
  const generation = amneziaSetup.generation, token = state.token, base = state.base, origin = location.origin;
  const target = $("amneziaSetupTarget").value;
  const username = $("amneziaSetupUsername").value.trim();
  const method = $("amneziaSetupAuthKey").checked ? "private_key" : "password";
  const file = method === "private_key" ? $("amneziaSetupPrivateKey").files?.[0] : null;
  const submittedPassphrase = method === "private_key" ? $("amneziaSetupPassphrase").value : "";
  if (!["awg2", "wireguard"].includes(target) || !/^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/.test(username) ||
      (method === "private_key" && (!file || file.size < 1 || file.size > 65536))) {
    showError($("amneziaSetupError"), "Укажите SSH-пользователя и выберите ключ до 64 КиБ, если входите по ключу.");
    return;
  }
  amneziaSetup.busy = true;
  clearError($("amneziaSetupError"));
  amneziaSetupDiscardReview();
  amneziaSetupRender();
  let password = "", private_key = "", passphrase = "";
  try {
    if (method === "private_key") {
      try { private_key = await file.text(); }
      catch { throw new Error("KEY_READ_FAILED"); }
      passphrase = submittedPassphrase;
    } else password = $("amneziaSetupPassword").value;
    if (!amneziaSetupCurrent(generation, token, base, origin) || amneziaSetup.fingerprint !== fingerprint ||
        amneziaSetupPin() !== previousPin || amneziaSetup.changedPin || !$("amneziaSetupTrust").checked ||
        username !== $("amneziaSetupUsername").value.trim() ||
        (method === "private_key" && (file !== $("amneziaSetupPrivateKey").files?.[0] ||
          submittedPassphrase !== $("amneziaSetupPassphrase").value)) ||
        target !== $("amneziaSetupTarget").value ||
        method !== ($("amneziaSetupAuthKey").checked ? "private_key" : "password")) return;
    if ((method === "password" && (!password || password.length > 1024)) ||
        (method === "private_key" && (!private_key || new TextEncoder().encode(private_key).length > 65536)) ||
        passphrase.length > 1024) throw new Error("INVALID_INPUT");
    amneziaSetupClearSecrets();
    if (endpoint) {
      const status = await amneziaSetupApi("/api/v1/browser-ssh/target-status",
        { ...endpoint, username, method, fingerprint, password, private_key, passphrase }, token, 30000);
      if (!amneziaSetupCurrent(generation, token, base, origin) || !amneziaSetupSameEndpoint()) return;
      if (status?.protocol !== 1 || status.scope !== "entered_target" ||
          status.host !== endpoint.host || status.port !== endpoint.port ||
          status.host_key_fingerprint !== fingerprint ||
          !["managed", "agent_only"].includes(status.kind)) throw new Error("TARGET_NOT_READY");
    }
    const result = await amneziaSetupApi("/api/v1/browser-ssh/vpn-setup/preview",
      { username, method, fingerprint, password, private_key, passphrase, target,
        ...(endpoint ?? {}) }, token, 75000);
    password = private_key = passphrase = "";
    if (!amneziaSetupCurrent(generation, token, base, origin)) return;
    if (!amneziaSetupValidResult(result, target)) throw new Error("INVALID_RESPONSE");
    amneziaSetupSavePin(fingerprint);
    amneziaSetupMarkPending(false);
    amneziaSetupShowStatus(result);
  } catch (failure) {
    if (amneziaSetupCurrent(generation, token, base, origin)) showError($("amneziaSetupError"),
      failure.message === "KEY_READ_FAILED" ? "Не удалось прочитать выбранный файл ключа." : amneziaSetupExplain(failure));
  } finally {
    password = private_key = passphrase = "";
    amneziaSetupClearSecrets();
    if (amneziaSetup.generation === generation) amneziaSetup.busy = false;
    amneziaSetupRender();
  }
}

function amneziaSetupValidEnrollment(result, target, fingerprint) {
  const fields = amneziaSetup.endpoint ? [...AMNEZIA_ENROLL_FIELDS, ...AMNEZIA_REMOTE_FIELDS].sort() :
    AMNEZIA_ENROLL_FIELDS;
  if (!result || typeof result !== "object" || Array.isArray(result) ||
      JSON.stringify(Object.keys(result).sort()) !== JSON.stringify(fields) ||
      result.protocol !== 1 || result.action !== "enroll_preview" || result.writes !== false ||
      result.reverify_required !== true || result.target !== target ||
      result.host_key_fingerprint !== fingerprint ||
      (amneziaSetup.endpoint && (result.scope !== "entered_target" ||
        result.host !== amneziaSetup.endpoint.host || result.port !== amneziaSetup.endpoint.port)) ||
      result.vpn_protocol !== (target === "awg2" ? "amneziawg" : "wireguard") ||
      result.interface !== (target === "awg2" ? "awg0" : "wg0") ||
      !Number.isSafeInteger(result.configured_clients) || result.configured_clients < 0 ||
      !Number.isSafeInteger(result.listen_port) || result.listen_port < 1 || result.listen_port > 65535 ||
      !/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(result.server_subnet)) return false;
  return ["container_id", "config_sha256", "table_sha256"].every((key) =>
    typeof result[key] === "string" && /^[0-9a-f]{64}$/.test(result[key])) &&
    typeof result.image_id === "string" && /^sha256:[0-9a-f]{64}$/.test(result.image_id);
}

function amneziaSetupValidActionIdentity(result) {
  if (amneziaSetup.endpoint) return result?.scope === "entered_target" &&
    result.host === amneziaSetup.endpoint.host && result.port === amneziaSetup.endpoint.port &&
    result.host_key_fingerprint === amneziaSetup.fingerprint;
  return !["scope", "host", "port", "host_key_fingerprint"]
    .some((key) => Object.hasOwn(result ?? {}, key));
}

async function amneziaSetupCredentials({ requireReview = true } = {}) {
  const identity = amneziaSetupIdentity();
  const file = identity.method === "private_key" ? $("amneziaSetupPrivateKey").files?.[0] : null;
  const passphrase = identity.method === "private_key" ? $("amneziaSetupPassphrase").value : "";
  if (!["awg2", "wireguard"].includes(identity.target) ||
      !/^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/.test(identity.username) ||
      !/^SHA256:[A-Za-z0-9+/]{43}$/.test(identity.fingerprint || "") ||
      (identity.method === "private_key" && (!file || file.size < 1 || file.size > 65536))) {
    throw new Error("INVALID_INPUT");
  }
  let password = "", private_key = "";
  if (identity.method === "private_key") {
    try { private_key = await file.text(); } catch { throw new Error("KEY_READ_FAILED"); }
  } else password = $("amneziaSetupPassword").value;
  if ((requireReview && !amneziaSetupSameIdentity()) ||
      Object.keys(identity).some((key) => amneziaSetupIdentity()[key] !== identity[key]) ||
      !amneziaSetupSameEndpoint() ||
      (identity.method === "private_key" && (file !== $("amneziaSetupPrivateKey").files?.[0] ||
        passphrase !== $("amneziaSetupPassphrase").value)) ||
      (identity.method === "password" && password !== $("amneziaSetupPassword").value) ||
      (identity.method === "password" && (!password || password.length > 1024)) ||
      (identity.method === "private_key" && (!private_key || new TextEncoder().encode(private_key).length > 65536)) ||
      passphrase.length > 1024) throw new Error("INVALID_INPUT");
  return { username: identity.username, method: identity.method, fingerprint: identity.fingerprint,
    password, private_key, passphrase, target: identity.target,
    ...(amneziaSetup.endpoint ?? {}) };
}

function amneziaSourceValid(result) {
  const endpoint = amneziaSetup.endpoint;
  const hashes = ["source_manifest_sha256", "candidate_sha256", "installed_sha256", "state_sha256"];
  return !!endpoint && result?.protocol === 1 && result.scope === "entered_target" &&
    result.host === endpoint.host && result.port === endpoint.port &&
    result.host_key_fingerprint === amneziaSetup.fingerprint &&
    hashes.every((key) => typeof result[key] === "string" && /^[0-9a-f]{64}$/.test(result[key]) &&
      result.expected?.[key] === result[key]) &&
    Object.keys(result.expected ?? {}).length === hashes.length &&
    ["install", "update", "current"].includes(result.change) &&
    result.temporary_writes === true && result.activation_writes === false &&
    typeof result.cleanup_required === "boolean";
}

async function amneziaSourcePreview() {
  if (!amneziaSetupAllowed() || amneziaSetup.busy || !amneziaSetupRemote() ||
      !amneziaSetup.fingerprint || amneziaSetup.changedPin ||
      !$("amneziaSetupTrust").checked || !amneziaSetupSameEndpoint()) return;
  const identity = amneziaSetupIdentity();
  const endpoint = amneziaSetup.endpoint;
  const generation = amneziaSetup.generation, token = state.token, base = state.base, origin = location.origin;
  amneziaSetup.busy = true;
  amneziaSetupDiscardSource();
  amneziaSetupDiscardReview();
  clearError($("amneziaSetupError"));
  amneziaSetupRender();
  let payload;
  try {
    payload = await amneziaSetupCredentials({ requireReview: false });
    if (!amneziaSetupCurrent(generation, token, base, origin) || !amneziaSetupSameEndpoint() ||
        Object.keys(identity).some((key) => amneziaSetupIdentity()[key] !== identity[key]) ||
        amneziaSetup.changedPin || !$("amneziaSetupTrust").checked) return;
    const { target: _target, ...login } = payload;
    amneziaSetupClearSecrets();
    const status = await amneziaSetupApi("/api/v1/browser-ssh/target-status", login, token, 30000);
    if (!amneziaSetupCurrent(generation, token, base, origin) || !amneziaSetupSameEndpoint()) return;
    if (status?.protocol !== 1 || status.scope !== "entered_target" ||
        status.host !== endpoint.host || status.port !== endpoint.port ||
        status.host_key_fingerprint !== identity.fingerprint ||
        !["managed", "agent_only"].includes(status.kind)) throw new Error("TARGET_NOT_READY");
    const result = await amneziaSetupApi("/api/v1/browser-ssh/vpn-source/preview", login, token, 720000);
    if (!amneziaSetupCurrent(generation, token, base, origin) || !amneziaSetupSameEndpoint() ||
        Object.keys(identity).some((key) => amneziaSetupIdentity()[key] !== identity[key])) return;
    if (!amneziaSourceValid(result)) throw new Error("INVALID_RESPONSE");
    amneziaSetupSavePin(identity.fingerprint);
    amneziaSetupMarkPending(false);
    amneziaSetup.source = result;
    amneziaSetup.sourceIdentity = identity;
    $("amneziaSourceSummary").textContent = result.cleanup_required
      ? "После предыдущей операции остались собственные временные файлы SovaGrid. Завершите очистку и проверьте пакет снова."
      : result.change === "current" ? "Совместимый VPN-код уже готов на сервере."
        : result.change === "install" ? "VPN-код отсутствует. Можно подготовить его на этом сервере."
          : "Найден более старый VPN-код. Обновление доступно только до установки брокера управления; существующий брокер мастер не заменит.";
    $("amneziaSourceDigest").textContent = result.candidate_sha256;
    $("amneziaSourceNotice").textContent = "";
  } catch (failure) {
    if (amneziaSetupCurrent(generation, token, base, origin)) {
      if (["STAGE_CLEANUP_REQUIRED", "RECOVERY_REQUIRED"].includes(failure.message) &&
          amneziaSetupSameEndpoint() && !amneziaSetup.changedPin && $("amneziaSetupTrust").checked) {
        amneziaSetup.source = { change: "current", cleanup_required: true, recovery_only: true };
        amneziaSetup.sourceIdentity = identity;
        $("amneziaSourceSummary").textContent =
          "Осталась собственная временная подготовка SovaGrid. Завершите очистку и проверьте пакет заново.";
        $("amneziaSourceDigest").textContent = "Отпечаток доступен после очистки.";
      }
      showError($("amneziaSetupError"), failure.message === "KEY_READ_FAILED"
        ? "Не удалось прочитать выбранный файл ключа." : amneziaSetupExplain(failure));
    }
  } finally {
    payload = null;
    amneziaSetupClearSecrets();
    if (amneziaSetup.generation === generation) amneziaSetup.busy = false;
    amneziaSetupRender();
  }
}

async function amneziaSourceAction(action) {
  const source = amneziaSetup.source;
  if (!amneziaSetupAllowed() || amneziaSetup.busy || !amneziaSetupRemote() || !source ||
      !amneziaSourceSameIdentity() || !amneziaSetupSameEndpoint() ||
      amneziaSetup.changedPin || !$("amneziaSetupTrust").checked ||
      !((action === "apply" && source.change !== "current" && !source.cleanup_required) ||
        (action === "recover" && source.cleanup_required))) return;
  const generation = amneziaSetup.generation, token = state.token, base = state.base, origin = location.origin;
  amneziaSetup.busy = true;
  clearError($("amneziaSetupError"));
  amneziaSetupRender();
  let payload;
  try {
    payload = await amneziaSetupCredentials({ requireReview: false });
    if (!amneziaSetupCurrent(generation, token, base, origin) || !amneziaSourceSameIdentity() ||
        amneziaSetup.changedPin || !$("amneziaSetupTrust").checked) return;
    const { target: _target, ...login } = payload;
    amneziaSetupClearSecrets();
    amneziaSetupMarkPending(true);
    const result = await amneziaSetupApi(`/api/v1/browser-ssh/vpn-source/${action}`,
      action === "apply" ? { ...login, expected: source.expected } : login, token, 720000);
    if (!amneziaSetupCurrent(generation, token, base, origin) || !amneziaSourceSameIdentity()) return;
    if (result?.protocol !== 1 || result.scope !== "entered_target" ||
        result.host !== amneziaSetup.endpoint.host || result.port !== amneziaSetup.endpoint.port ||
        result.host_key_fingerprint !== amneziaSetup.fingerprint ||
        (action === "apply" && (result.installed !== true || typeof result.changed !== "boolean" ||
          typeof result.cleanup_required !== "boolean" || result.cleanup_required ||
          result.source_manifest_sha256 !== source.source_manifest_sha256 ||
          result.candidate_sha256 !== source.candidate_sha256)) ||
        (action === "recover" && typeof result.recovered !== "boolean")) {
      throw new Error("SETUP_UNCERTAIN");
    }
    amneziaSetupMarkPending(false);
    amneziaSetupDiscardSource();
    amneziaSetupDiscardReview();
    $("amneziaSourceNotice").textContent = action === "apply"
      ? "VPN-код подготовлен. Теперь покажите состояние Amnezia и продолжите настройку брокера."
      : "Очистка завершена. Проверьте VPN-код снова перед следующим действием.";
  } catch (failure) {
    if (amneziaSetupCurrent(generation, token, base, origin)) {
      amneziaSetupDiscardSource();
      if (["INVALID_INPUT", "AUTH_FAILED", "HOST_KEY_CHANGED", "STALE_REVISION",
           "STALE_PREVIEW", "SOURCE_CHANGED", "STATE_CONFLICT", "OWNERSHIP_CONFLICT",
           "CONTROL_ACTIVE", "ROOT_REQUIRED"].includes(failure.message))
        amneziaSetupMarkPending(false);
      showError($("amneziaSetupError"), failure.message === "KEY_READ_FAILED"
        ? "Не удалось прочитать выбранный файл ключа." : amneziaSetupExplain(failure));
    }
  } finally {
    payload = null;
    amneziaSetupClearSecrets();
    if (amneziaSetup.generation === generation) amneziaSetup.busy = false;
    amneziaSetupRender();
  }
}

function wgControlPendingKey() {
  let endpoint = amneziaSetup.endpoint;
  if (!endpoint) {
    try { endpoint = amneziaSetupEndpoint(); } catch { /* Address not selected yet. */ }
  }
  return `sovagrid.wg-control-pending:${location.origin}:${endpoint
    ? `${endpoint.host}:${endpoint.port}` : "unselected_target"}`;
}
function wgControlPending() {
  try { return sessionStorage.getItem(wgControlPendingKey()) === "1"; } catch { return false; }
}
function wgControlMarkPending(pending) {
  try {
    if (pending) sessionStorage.setItem(wgControlPendingKey(), "1");
    else sessionStorage.removeItem(wgControlPendingKey());
  } catch { /* Private browsing may disable storage. */ }
}
function wgControlSameIdentity() {
  try {
    const current = amneziaSetupIdentity(), reviewed = wgControl.identity;
    return reviewed && Object.keys(current).every((key) => current[key] === reviewed[key]);
  } catch { return false; }
}
function wgControlReady() {
  return amneziaSetupRemote() && amneziaSetupAllowed() && !amneziaSetup.busy &&
    !amneziaSetupPending() && !!amneziaSetup.fingerprint && !amneziaSetup.changedPin &&
    $("amneziaSetupTrust").checked && amneziaSetupSameEndpoint();
}
function wgControlRender() {
  $("wgControlPanel").hidden = !amneziaSetupRemote();
  const ready = wgControlReady(), reviewed = ready && wgControlSameIdentity() && wgControl.preview;
  $("wgControlPreview").disabled = !ready;
  $("wgControlReview").hidden = !reviewed;
  $("wgControlApply").hidden = !reviewed || wgControl.preview.can_apply !== true ||
    wgControl.preview.pending_recovery === true || wgControlPending();
  $("wgControlRecover").hidden = !reviewed || wgControl.preview.pending_recovery !== true;
  if (wgControlPending() && !wgControl.preview && !$("wgControlNotice").textContent) {
    $("wgControlNotice").textContent =
      "Предыдущее действие могло продолжиться после потери связи. Сначала проверьте состояние заново.";
  }
}
function wgControlReset() {
  wgControl.preview = null;
  wgControl.identity = null;
  wgControl.pendingAction = null;
  if ($("wgControlDialog").open) $("wgControlDialog").close();
  $("wgControlReview").hidden = true;
  $("wgControlSummary").textContent = "";
  $("wgControlDetails").textContent = "";
  $("wgControlDigest").textContent = "";
  $("wgControlNotice").textContent = "";
  clearError($("wgControlError"));
  wgControlRender();
}
function wgControlValidScope(value) {
  return value?.protocol === 1 && value.scope === "entered_target" &&
    value.host === amneziaSetup.endpoint?.host && value.port === amneziaSetup.endpoint?.port &&
    value.host_key_fingerprint === amneziaSetup.fingerprint;
}
function wgControlValidPreview(value) {
  if (!wgControlValidScope(value) || value.schema_version !== 1 ||
      value.action !== "preview" || value.writes !== false ||
      typeof value.can_apply !== "boolean" || typeof value.pending_recovery !== "boolean") return false;
  const reason = value.reason;
  if (reason !== undefined && !["SOURCE_NOT_PREPARED", "SOURCE_CHANGED", "AGENT_UNAVAILABLE",
      "DEPENDENCIES_UNAVAILABLE", "RECOVERY_REQUIRED", "CONTROL_ACTIVE", "BUSY",
      "OPERATION_FAILED", "ROOT_REQUIRED", "SSH_UNAVAILABLE", "STALE_PREVIEW"].includes(reason)) return false;
  if (value.state_revision === undefined && value.source_revision === undefined) {
    return value.can_apply === false && typeof reason === "string";
  }
  const boolFields = ["installed_current", "socket_active", "service_active", "socket_enabled",
    "inventory_timer_active", "inventory_timer_enabled", "inventory_snapshot_present",
    "apparmor_profile_present", "requires_service_restart"];
  return ["state_revision", "source_revision"].every((key) =>
    typeof value[key] === "string" && /^[0-9a-f]{64}$/.test(value[key])) &&
    boolFields.every((key) => typeof value[key] === "boolean") &&
    Array.isArray(value.missing_dependencies) && value.missing_dependencies.length <= 5 &&
    new Set(value.missing_dependencies).size === value.missing_dependencies.length &&
    value.missing_dependencies.every((name) =>
      ["wg", "wg-quick", "ip", "python3-cryptography", "apparmor_parser"].includes(name)) &&
    (value.can_apply ? reason === undefined : typeof reason === "string");
}
function wgControlReason(reason) {
  const labels = {
    SOURCE_NOT_PREPARED: "Сначала подготовьте VPN-код в шаге выше и проверьте брокер снова.",
    SOURCE_CHANGED: "VPN-код на сервере изменился. Проверьте пакет снова перед установкой.",
    AGENT_UNAVAILABLE: "На сервере не найден нужный Agent или его группа. Сначала установите Agent.",
    DEPENDENCIES_UNAVAILABLE: "Не удалось подготовить зависимости WireGuard. Проверьте пакеты сервера.",
    RECOVERY_REQUIRED: "Осталась незавершённая установка. Сначала выполните восстановление и повторите проверку.",
    CONTROL_ACTIVE: "Работающий брокер нельзя заменить этим мастером. Проверьте его в окно обслуживания.",
    BUSY: "Сервер занят другой операцией. Повторите проверку позже.",
    ROOT_REQUIRED: "Нужен SSH-вход root или sudo без запроса пароля.",
  };
  return labels[reason] || "Брокер пока нельзя установить. Проверьте сервер и повторите предпросмотр.";
}
function wgControlShowPreview(value) {
  wgControl.preview = value;
  wgControl.identity = amneziaSetupIdentity();
  $("wgControlSummary").textContent = value.pending_recovery ? wgControlReason("RECOVERY_REQUIRED") :
    value.can_apply ? value.installed_current && value.socket_active && value.inventory_timer_active
      ? "Брокер WireGuard уже установлен и работает. Можно повторно применить проверенное состояние при необходимости."
      : "Сервер готов к установке WireGuard-брокера. VPN-интерфейс останется выключенным."
      : wgControlReason(value.reason);
  $("wgControlDetails").textContent = !value.state_revision ? "Подробный снимок пока недоступен." :
    `Сокет: ${value.socket_active ? "работает" : "не запущен"}. Служба: ${value.service_active ? "работает" : "не запущена"}. ` +
    `Таймер мониторинга: ${value.inventory_timer_active ? "работает" : "не запущен"}. ` +
    `Недостающие пакеты: ${value.missing_dependencies.length ? value.missing_dependencies.join(", ") : "нет"}.` +
    (value.requires_service_restart ? " Для установки потребуется перезапуск службы брокера." : "");
  $("wgControlRevisions").hidden = !value.state_revision;
  $("wgControlDigest").textContent = value.state_revision ?
    `Состояние: ${value.state_revision}\nVPN-код: ${value.source_revision}` : "";
  $("wgControlNotice").textContent = "";
  wgControlRender();
}
function wgControlExplain(failure) {
  if (["APPLY_UNCERTAIN", "RECOVERY_UNCERTAIN", "SSH_TIMEOUT", "INSTALLER_UNAVAILABLE",
    "SSH_UNAVAILABLE", "OPERATION_FAILED"].includes(failure.message)) {
    return "Ответ потерян или не подтверждён. Действие могло выполниться: сначала проверьте состояние заново, затем решайте, нужно ли восстановление.";
  }
  if (failure.message === "STALE_PREVIEW") return "Состояние изменилось после проверки. Откройте новый предпросмотр.";
  if (failure.message === "RECOVERY_REQUIRED") return wgControlReason("RECOVERY_REQUIRED");
  if (failure.message === "SOURCE_NOT_PREPARED") return wgControlReason("SOURCE_NOT_PREPARED");
  if (failure.message === "AGENT_UNAVAILABLE") return wgControlReason("AGENT_UNAVAILABLE");
  if (failure.message === "DEPENDENCIES_UNAVAILABLE") return wgControlReason("DEPENDENCIES_UNAVAILABLE");
  if (failure.message === "CONTROL_ACTIVE") return wgControlReason("CONTROL_ACTIVE");
  if (failure.message === "KEY_READ_FAILED") return "Не удалось прочитать выбранный файл ключа.";
  return amneziaSetupExplain(failure);
}
async function wgControlPreview() {
  if (!wgControlReady()) return;
  const identity = amneziaSetupIdentity(), endpoint = amneziaSetup.endpoint;
  const generation = amneziaSetup.generation, token = state.token, base = state.base, origin = location.origin;
  amneziaSetup.busy = true;
  wgControlReset();
  amneziaSetupRender();
  let login;
  try {
    const credentials = await amneziaSetupCredentials({ requireReview: false });
    if (!amneziaSetupCurrent(generation, token, base, origin) || !amneziaSetupSameEndpoint() ||
        Object.keys(identity).some((key) => amneziaSetupIdentity()[key] !== identity[key])) return;
    const { target: _target, ...selected } = credentials;
    login = selected;
    amneziaSetupClearSecrets();
    const status = await amneziaSetupApi("/api/v1/browser-ssh/target-status", login, token, 30000);
    if (!amneziaSetupCurrent(generation, token, base, origin) || !amneziaSetupSameEndpoint()) return;
    if (status?.protocol !== 1 || status.scope !== "entered_target" ||
        status.host !== endpoint.host || status.port !== endpoint.port ||
        status.host_key_fingerprint !== identity.fingerprint ||
        !["managed", "agent_only"].includes(status.kind)) throw new Error("TARGET_NOT_READY");
    const result = await amneziaSetupApi("/api/v1/browser-ssh/wg-control/preview", login, token, 130000);
    if (!amneziaSetupCurrent(generation, token, base, origin) || !amneziaSetupSameEndpoint() ||
        Object.keys(identity).some((key) => amneziaSetupIdentity()[key] !== identity[key])) return;
    if (!wgControlValidPreview(result)) throw new Error("INVALID_RESPONSE");
    amneziaSetupSavePin(identity.fingerprint);
    wgControlMarkPending(false);
    wgControlShowPreview(result);
  } catch (failure) {
    if (amneziaSetupCurrent(generation, token, base, origin))
      showError($("wgControlError"), wgControlExplain(failure));
  } finally {
    if (login) for (const key of ["password", "private_key", "passphrase"]) login[key] = "";
    amneziaSetupClearSecrets();
    if (amneziaSetup.generation === generation) amneziaSetup.busy = false;
    amneziaSetupRender();
  }
}
function wgControlConfirm(action) {
  if (!wgControlReady() || !wgControlSameIdentity() || !wgControl.preview ||
      !(action === "apply" ? wgControl.preview.can_apply && !wgControlPending() :
        action === "recover" && wgControl.preview.pending_recovery)) return;
  const host = `${amneziaSetup.endpoint.host}:${amneziaSetup.endpoint.port}`;
  $("wgControlDialogTitle").textContent = action === "apply" ?
    "Установить WireGuard-брокер?" : "Завершить восстановление WireGuard?";
  $("wgControlDialogSummary").textContent = action === "apply" ?
    `SovaGrid установит пакеты, включит сокет и таймер мониторинга на ${host}. VPN-интерфейс и клиентские профили не изменятся.` :
    `SovaGrid проверит и завершит собственную прерванную установку на ${host}. VPN-интерфейс не будет включён.`;
  wgControl.pendingAction = action;
  $("wgControlDialog").showModal();
}
async function wgControlAction(action) {
  const preview = wgControl.preview;
  if (!wgControlReady() || !wgControlSameIdentity() || !preview ||
      !(action === "apply" ? preview.can_apply && !wgControlPending() :
        action === "recover" && preview.pending_recovery)) return;
  const identity = wgControl.identity;
  const generation = amneziaSetup.generation, token = state.token, base = state.base, origin = location.origin;
  amneziaSetup.busy = true;
  clearError($("wgControlError"));
  amneziaSetupRender();
  let login;
  try {
    const credentials = await amneziaSetupCredentials({ requireReview: false });
    if (!amneziaSetupCurrent(generation, token, base, origin) || !wgControlSameIdentity() ||
        Object.keys(identity).some((key) => amneziaSetupIdentity()[key] !== identity[key])) return;
    const { target: _target, ...selected } = credentials;
    login = selected;
    amneziaSetupClearSecrets();
    wgControlMarkPending(true);
    const payload = action === "apply" ? { ...login, expected: {
      state_revision: preview.state_revision, source_revision: preview.source_revision }, confirm: true } :
      { ...login, confirm: true };
    const result = await amneziaSetupApi(`/api/v1/browser-ssh/wg-control/${action}`, payload,
      token, action === "apply" ? 735000 : 465000);
    if (!amneziaSetupCurrent(generation, token, base, origin) || !wgControlSameIdentity()) return;
    if (!wgControlValidScope(result) || (action === "apply" &&
        (result.action !== "installed" || result.socket_active !== true || result.service_active !== true ||
         result.inventory_timer_active !== true || result.inventory_snapshot_present !== true ||
         result.vpn_interface_changed !== false || result.source_revision !== preview.source_revision)) ||
        (action === "recover" && (result.action !== "recovered" || typeof result.changed !== "boolean"))) {
      throw new Error(action === "apply" ? "APPLY_UNCERTAIN" : "RECOVERY_UNCERTAIN");
    }
    wgControlMarkPending(false);
    wgControlReset();
    $("wgControlNotice").textContent = action === "apply" ?
      "Брокер, сокет и мониторинг WireGuard готовы. VPN-интерфейс не включён. Проверьте состояние снова." :
      "Восстановление завершено. Проверьте WireGuard-брокер снова перед установкой.";
  } catch (failure) {
    if (amneziaSetupCurrent(generation, token, base, origin)) {
      if (["INVALID_INPUT", "AUTH_FAILED", "AUTH_REQUIRED", "ADMIN_FORBIDDEN", "HOST_KEY_CHANGED",
           "STALE_PREVIEW", "RECOVERY_REQUIRED", "CONTROL_ACTIVE", "SOURCE_NOT_PREPARED",
           "SOURCE_CHANGED", "AGENT_UNAVAILABLE", "DEPENDENCIES_UNAVAILABLE", "ROOT_REQUIRED",
           "BUSY"].includes(failure.message)) wgControlMarkPending(false);
      wgControlReset();
      showError($("wgControlError"), wgControlExplain(failure));
    }
  } finally {
    if (login) for (const key of ["password", "private_key", "passphrase"]) login[key] = "";
    amneziaSetupClearSecrets();
    if (amneziaSetup.generation === generation) amneziaSetup.busy = false;
    amneziaSetupRender();
  }
}

async function amneziaSetupAction(action) {
  if (!amneziaSetupAllowed() || amneziaSetup.busy || !amneziaSetupSameIdentity() ||
      !amneziaSetup.fingerprint || amneziaSetup.changedPin || !$("amneziaSetupTrust").checked ||
      !["enroll-preview", "enroll", "install", "arm"].includes(action)) return;
  const generation = amneziaSetup.generation, token = state.token, base = state.base, origin = location.origin;
  const reviewed = action === "enroll" ? amneziaSetup.enrollment : amneziaSetup.setup;
  if ((action === "enroll" && !reviewed) || (action !== "enroll-preview" && !reviewed)) return;
  if (action === "enroll-preview") {
    amneziaSetup.enrollment = null;
    $("amneziaSetupEnrollment").hidden = true;
    $("amneziaSetupEnrollmentSummary").textContent = "";
    $("amneziaSetupEnrollmentPins").textContent = "";
  }
  amneziaSetup.busy = true;
  clearError($("amneziaSetupError"));
  amneziaSetupRender();
  let payload;
  try {
    payload = await amneziaSetupCredentials();
    if (!amneziaSetupCurrent(generation, token, base, origin) || !amneziaSetupSameIdentity() ||
        amneziaSetup.changedPin || !$("amneziaSetupTrust").checked) return;
    if (action !== "enroll-preview") {
      payload.reviewed = reviewed;
      payload.confirm = action === "arm" ? AMNEZIA_SETUP_CONFIRM[payload.target] : AMNEZIA_SETUP_CONFIRM[action];
    }
    amneziaSetupClearSecrets();
    if (action !== "enroll-preview") amneziaSetupMarkPending(true);
    const result = await amneziaSetupApi(`/api/v1/browser-ssh/vpn-setup/${action}`,
      payload, token, action === "enroll-preview" ? 75000 : 170000);
    if (!amneziaSetupCurrent(generation, token, base, origin)) return;
    if (action === "enroll-preview") {
      if (!amneziaSetupValidEnrollment(result, payload.target, payload.fingerprint)) throw new Error("INVALID_RESPONSE");
      amneziaSetup.enrollment = result;
      $("amneziaSetupEnrollmentSummary").textContent =
        `${result.vpn_protocol === "amneziawg" ? "AmneziaWG" : "WireGuard"} · ${result.server_subnet} · UDP ${result.listen_port} · клиентов: ${result.configured_clients}.`;
      $("amneziaSetupEnrollmentPins").textContent =
        `Контейнер ${result.container_id}\nОбраз ${result.image_id}\nКонфигурация ${result.config_sha256}\nТаблица клиентов ${result.table_sha256}`;
      $("amneziaSetupEnrollment").hidden = false;
    } else {
      if (result?.protocol !== 1 || result.target !== payload.target ||
          result.action !== ({ enroll: "enrolled", install: "installed", arm: "armed" })[action] ||
          !amneziaSetupValidActionIdentity(result)) {
        throw new Error("SETUP_UNCERTAIN");
      }
      amneziaSetupShowStatus(result.setup);
      amneziaSetupMarkPending(false);
    }
  } catch (failure) {
    if (amneziaSetupCurrent(generation, token, base, origin)) {
      if (action !== "enroll-preview") amneziaSetupDiscardReview();
      if (failure.message === "SETUP_CHANGED" || failure.message === "INVALID_INPUT" ||
          failure.message === "AUTH_FAILED" || failure.message === "HOST_KEY_CHANGED") amneziaSetupMarkPending(false);
      showError($("amneziaSetupError"), failure.message === "KEY_READ_FAILED"
        ? "Не удалось прочитать выбранный файл ключа." : amneziaSetupExplain(failure));
    }
  } finally {
    payload = null;
    amneziaSetupClearSecrets();
    if (amneziaSetup.generation === generation) amneziaSetup.busy = false;
    amneziaSetupRender();
  }
}

function amneziaSetupConfirm(action) {
  if (amneziaSetup.busy || !amneziaSetupSameIdentity() || !amneziaSetupAllowed() ||
      !amneziaSetup.fingerprint || amneziaSetup.changedPin || !$("amneziaSetupTrust").checked) return;
  const setup = amneziaSetup.setup;
  if (action === "enroll" && !amneziaSetup.enrollment ||
      action === "install" && (!setup?.enrolled || !setup.installer_ready || setup.installed_current) ||
      action === "arm" && (!setup?.can_arm || !setup.installed_current)) return;
  const labels = { enroll: "Подключить существующий контейнер", install: "Установить брокер управления",
    arm: "Включить управление VPN" };
  const host = amneziaSetup.endpoint ? `${amneziaSetup.endpoint.host}:${amneziaSetup.endpoint.port}` :
    location.hostname;
  $("amneziaSetupDialogTitle").textContent = labels[action];
  $("amneziaSetupDialogSummary").textContent = action === "enroll"
    ? `SovaGrid подключит существующий контейнер ${amneziaSetup.enrollment.vpn_protocol} на ${host}. Клиентов: ${amneziaSetup.enrollment.configured_clients}.`
    : action === "install" ? `Установить локальный брокер на ${host}. VPN-контейнер не будет перезапущен.`
      : `Включить брокер для ${setup.target === "awg2" ? "AmneziaWG" : "WireGuard"} на ${host}. Клиентские подключения могут прерваться.`;
  $("amneziaSetupMaintenanceLabel").hidden = action !== "arm";
  $("amneziaSetupMaintenance").checked = false;
  amneziaSetup.pendingAction = action;
  $("amneziaSetupDialog").showModal();
}

function amneziaSourceConfirm(action) {
  const source = amneziaSetup.source;
  if (!amneziaSetupAllowed() || amneziaSetup.busy || !amneziaSourceSameIdentity() ||
      !amneziaSetupSameEndpoint() || amneziaSetup.changedPin || !$("amneziaSetupTrust").checked ||
      !((action === "apply" && source?.change !== "current" && !source?.cleanup_required) ||
        (action === "recover" && source?.cleanup_required))) return;
  const host = `${amneziaSetup.endpoint.host}:${amneziaSetup.endpoint.port}`;
  $("amneziaSetupDialogTitle").textContent = action === "apply"
    ? "Подготовить VPN-код" : "Завершить очистку VPN-кода";
  $("amneziaSetupDialogSummary").textContent = action === "apply"
    ? `SovaGrid установит проверенный VPN-код на ${host}. VPN-контейнер и работающие службы не меняются. Пакет: ${source.candidate_sha256}.`
    : `SovaGrid очистит только собственные временные файлы подготовки на ${host}.`;
  $("amneziaSetupMaintenanceLabel").hidden = true;
  $("amneziaSetupMaintenance").checked = false;
  amneziaSetup.pendingAction = `source-${action}`;
  $("amneziaSetupDialog").showModal();
}

$("amneziaSetupInspect").addEventListener("click", () => { void amneziaSetupInspect(); });
$("amneziaSetupForm").addEventListener("submit", (event) => { void amneziaSetupPreview(event); });
$("amneziaSourcePreview").addEventListener("click", () => { void amneziaSourcePreview(); });
$("amneziaSourceApply").addEventListener("click", () => amneziaSourceConfirm("apply"));
$("amneziaSourceRecover").addEventListener("click", () => amneziaSourceConfirm("recover"));
$("wgControlPreview").addEventListener("click", () => { void wgControlPreview(); });
$("wgControlApply").addEventListener("click", () => wgControlConfirm("apply"));
$("wgControlRecover").addEventListener("click", () => wgControlConfirm("recover"));
$("wgControlDialogCancel").addEventListener("click", () => $("wgControlDialog").close());
$("wgControlDialog").addEventListener("close", () => { wgControl.pendingAction = null; });
$("wgControlDialogConfirm").addEventListener("click", () => {
  const action = wgControl.pendingAction;
  if (!action) return;
  $("wgControlDialog").close();
  void wgControlAction(action);
});
$("amneziaSetupEnrollPreview").addEventListener("click", () => { void amneziaSetupAction("enroll-preview"); });
$("amneziaSetupEnroll").addEventListener("click", () => amneziaSetupConfirm("enroll"));
$("amneziaSetupInstall").addEventListener("click", () => amneziaSetupConfirm("install"));
$("amneziaSetupArm").addEventListener("click", () => amneziaSetupConfirm("arm"));
$("amneziaSetupDialogCancel").addEventListener("click", () => $("amneziaSetupDialog").close());
$("amneziaSetupDialog").addEventListener("close", () => { amneziaSetup.pendingAction = null; });
$("amneziaSetupDialogConfirm").addEventListener("click", () => {
  const action = amneziaSetup.pendingAction;
  if (!action || (action === "arm" && !$("amneziaSetupMaintenance").checked)) return;
  $("amneziaSetupDialog").close();
  if (action === "source-apply" || action === "source-recover")
    void amneziaSourceAction(action.slice("source-".length));
  else void amneziaSetupAction(action);
});
for (const id of ["amneziaSetupScopeLocal", "amneziaSetupScopeRemote"])
  $(id).addEventListener("change", amneziaSetupReset);
for (const id of ["amneziaSetupRemoteHost", "amneziaSetupRemotePort"])
  $(id).addEventListener("input", () => {
    amneziaSetup.generation++;
    amneziaSetup.controller?.abort();
    amneziaSetup.controller = null;
    amneziaSetup.busy = false;
    amneziaSetup.fingerprint = null;
    amneziaSetup.endpoint = null;
    amneziaSetup.changedPin = false;
    amneziaSetup.pendingAction = null;
    if ($("amneziaSetupDialog").open) $("amneziaSetupDialog").close();
    $("amneziaSetupTrust").checked = false;
    $("amneziaSetupHostKeyReview").hidden = true;
    $("amneziaSetupReplaceKey").hidden = true;
    amneziaSetupDiscardReview();
    amneziaSetupDiscardSource();
    amneziaSetupClearSecrets();
    clearError($("amneziaSetupError"));
    amneziaSetupRender();
  });
$("amneziaSetupTarget").addEventListener("change", amneziaSetupReset);
$("amneziaSetupAuthPassword").addEventListener("change", amneziaSetupMethodChanged);
$("amneziaSetupAuthKey").addEventListener("change", amneziaSetupMethodChanged);
$("amneziaSetupUsername").addEventListener("input", () => {
  amneziaSetupDiscardReview();
  amneziaSetupDiscardSource();
  amneziaSetupRender();
});
$("amneziaSetupTrust").addEventListener("change", () => {
  if (!$("amneziaSetupTrust").checked) {
    amneziaSetupDiscardReview();
    amneziaSetupDiscardSource();
  }
  amneziaSetupRender();
});
$("amneziaSetupReplaceKey").addEventListener("click", () => {
  if (!globalThis.confirm?.("Заменить закреплённый SSH-ключ после независимой сверки нового отпечатка?")) return;
  amneziaSetup.changedPin = false;
  $("amneziaSetupReplaceKey").hidden = true;
  $("amneziaSetupTrust").checked = false;
  amneziaSetupDiscardSource();
  clearError($("amneziaSetupError"));
  amneziaSetupRender();
});
for (const button of document.querySelectorAll("[data-view]")) {
  if (button.dataset.view !== "vpn") button.addEventListener("click", () => amneziaSetupReset());
}
document.addEventListener("visibilitychange", () => { if (document.hidden) amneziaSetupClearSecrets(); });
globalThis.addEventListener?.("pagehide", amneziaSetupClearSecrets);
amneziaSetupRender();

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

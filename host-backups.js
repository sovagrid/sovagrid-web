/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// The Hub and Web containers stop during a host snapshot. Keep only its
// request ID in browser storage; the root journal is the source of truth.
const HOST_BACKUP_MARKER = "sovagrid.host-backup-request.v1:";
const HOST_PORTABLE_DOWNLOAD_MARKER = "sovagrid.host-portable-download.v1:";
const HOST_BACKUP_ID = /^[0-9a-f]{32}$/;
const HOST_BACKUP_SHA = /^[0-9a-f]{64}$/;
const HOST_BACKUP_ERROR = /^[A-Z][A-Z0-9_]{1,63}$/;
const HOST_BACKUP_PHASES = Object.freeze({
  accepted: "Принято", stopping: "Останавливаем службы",
  archiving: "Создаём архив", restarting: "Запускаем службы",
  complete: "Копия создана", recovery_requested: "Исправление запрошено",
  recovered: "Службы восстановлены", failed: "Операция завершилась с ошибкой",
  recovery_required: "Нужно восстановить службы",
});
const HOST_BACKUP_FINAL = new Set(["complete", "recovered", "failed"]);
const HOST_PORTABLE_RECEIPT = "sovagrid-portable-host-receipt-v1";
const HOST_PORTABLE_RECEIPT_V2 = "sovagrid-portable-host-receipt-v2";
const HOST_UNIT_ENABLEMENT = new Set(["alias", "disabled", "enabled", "enabled-runtime", "generated", "indirect", "linked", "linked-runtime", "masked", "masked-runtime", "static", "transient"]);
const HOST_MANAGED_UNITS = {
  "full": new Set(`
    sovagrid-agent.service
    sovagrid-amnezia-control.service
    sovagrid-amnezia-control.socket
    sovagrid-auto-update.service
    sovagrid-auto-update.timer
    sovagrid-container-inventory.service
    sovagrid-container-inventory.timer
    sovagrid-hub-backup-control.service
    sovagrid-hub-backup-control.socket
    sovagrid-journal-control.service
    sovagrid-journal-control.socket
    sovagrid-release-feed.service
    sovagrid-release-feed.timer
    sovagrid-service-control.service
    sovagrid-service-control.socket
    sovagrid-terminal-control.service
    sovagrid-terminal-control.socket
    sovagrid-vpn-control.service
    sovagrid-vpn-control.socket
    sovagrid-vpn-routing.service
    sovagrid-vpn-status.service
    sovagrid-vpn-status.timer
    sovagrid-web-agent-control.service
    sovagrid-web-agent-control.socket
  `.trim().split(/\s+/)),
  "hub-only": new Set(`
    sovagrid-agent-local.service
    sovagrid-container-inventory-local.service
    sovagrid-container-inventory-local.timer
    sovagrid-external-agent-apply@.service
    sovagrid-external-agent-recovery.service
    sovagrid-hub-backup-control.service
    sovagrid-hub-backup-control.socket
    sovagrid-hub-only-update.service
    sovagrid-hub-only-update.timer
    sovagrid-release-feed.service
    sovagrid-release-feed.timer
    sovagrid-service-local-control.service
    sovagrid-service-local-control.socket
    sovagrid-terminal-local-control.service
    sovagrid-terminal-local-control.socket
    sovagrid-vpn-routing.service
    sovagrid-vpn-status.service
    sovagrid-vpn-status.timer
    sovagrid-web-agent-control.service
    sovagrid-web-agent-control.socket
  `.trim().split(/\s+/)),
};
const HOST_WRITER_UNITS = {
  "full": new Set(`
    sovagrid-amnezia-control.service
    sovagrid-amnezia-control.socket
    sovagrid-auto-update.service
    sovagrid-auto-update.timer
    sovagrid-container-inventory.service
    sovagrid-container-inventory.timer
    sovagrid-hub-backup-control.service
    sovagrid-hub-backup-control.socket
    sovagrid-release-feed.service
    sovagrid-release-feed.timer
    sovagrid-vpn-control.service
    sovagrid-vpn-control.socket
    sovagrid-vpn-status.service
    sovagrid-vpn-status.timer
    sovagrid-web-agent-control.service
    sovagrid-web-agent-control.socket
  `.trim().split(/\s+/)),
  "hub-only": new Set(`
    sovagrid-container-inventory-local.service
    sovagrid-container-inventory-local.timer
    sovagrid-hub-backup-control.service
    sovagrid-hub-backup-control.socket
    sovagrid-hub-only-update.service
    sovagrid-hub-only-update.timer
    sovagrid-release-feed.service
    sovagrid-release-feed.timer
    sovagrid-vpn-status.service
    sovagrid-vpn-status.timer
    sovagrid-web-agent-control.service
    sovagrid-web-agent-control.socket
  `.trim().split(/\s+/)),
};
const HOST_PORTABLE_PARTS = Object.freeze({
  archive: "Архив хоста", host_manifest: "Манифест хоста",
  images: "Образы контейнеров", images_manifest: "Манифест образов",
  receipt: "Квитанция",
});
function hostBackupPortableFilename(part, archiveId) {
  if (part === "archive") return `${archiveId}.tar.gz`;
  if (part === "host_manifest") return `${archiveId}.manifest.json`;
  if (part === "images") return "images.tar";
  if (part === "images_manifest") return "manifest.json";
  return "receipt.json";
}
function hostBackupPortableStagePath(part, archiveId) {
  const name = hostBackupPortableFilename(part, archiveId);
  return ["images", "images_manifest", "receipt"].includes(part)
    ? `${archiveId}/${name}` : name;
}
const hostBackupClient = {
  generation: 0, loading: false, checking: null, starting: false, recovering: false,
  plan: null, manifest: null, archives: [], operations: [], activeId: null,
  active: null, pending: null, pendingRecover: null, lastRefresh: 0,
  ready: false, uncertain: false, portableAvailable: false, activePortable: false,
  portableReceipt: null, portableVerified: null, portableGrant: null,
  portableDownloadPending: null,
};

function hostBackupCurrent(generation, token, base) {
  return hostBackupClient.generation === generation && state.token === token &&
    state.base === base && Boolean(token) && hubCanGlobalAdmin();
}

function hostBackupMarkerKey() { return HOST_BACKUP_MARKER + state.base; }

function hostBackupReadMarkerRecord() {
  try {
    const value = JSON.parse(localStorage.getItem(hostBackupMarkerKey()) || "null");
    const keys = value && typeof value === "object" && !Array.isArray(value)
      ? Object.keys(value).sort().join(",") : "";
    if (keys !== "base,request_id" && keys !== "base,mode,request_id") return null;
    if (value.base !== state.base || !HOST_BACKUP_ID.test(value.request_id) ||
        (value.mode !== undefined && value.mode !== "portable")) return null;
    return { requestId: value.request_id, mode: value.mode || "ordinary" };
  } catch { return null; }
}

function hostBackupReadMarker() { return hostBackupReadMarkerRecord()?.requestId || null; }

function hostBackupSaveMarker(requestId, mode = "ordinary") {
  if (!HOST_BACKUP_ID.test(requestId) || !["ordinary", "portable"].includes(mode)) return false;
  try {
    localStorage.setItem(hostBackupMarkerKey(),
      JSON.stringify(mode === "portable" ?
        { base: state.base, request_id: requestId, mode } :
        { base: state.base, request_id: requestId }));
    const saved = hostBackupReadMarkerRecord();
    return saved?.requestId === requestId && saved.mode === mode;
  } catch { return false; }
}

function hostBackupClearMarker(requestId) {
  try {
    if (hostBackupReadMarker() === requestId) localStorage.removeItem(hostBackupMarkerKey());
  } catch { /* The server record remains available without local storage. */ }
}

function hostBackupDownloadMarkerKey() { return HOST_PORTABLE_DOWNLOAD_MARKER + state.base; }

function hostBackupReadDownloadMarker() {
  try {
    const value = JSON.parse(localStorage.getItem(hostBackupDownloadMarkerKey()) || "null");
    if (!value || typeof value !== "object" || Array.isArray(value) ||
        Object.keys(value).sort().join(",") !== "base,part,request_id,started_at" ||
        value.base !== state.base || !HOST_BACKUP_ID.test(value.request_id) ||
        !Object.hasOwn(HOST_PORTABLE_PARTS, value.part) ||
        !Number.isSafeInteger(value.started_at) || value.started_at < 0 ||
        !Number.isFinite(new Date(value.started_at).getTime())) return null;
    return { requestId: value.request_id, part: value.part, startedAt: value.started_at };
  } catch { return null; }
}

function hostBackupSaveDownloadMarker(requestId, part) {
  if (!HOST_BACKUP_ID.test(requestId) || !Object.hasOwn(HOST_PORTABLE_PARTS, part) ||
      hostBackupReadDownloadMarker()) return null;
  const startedAt = Date.now();
  try {
    localStorage.setItem(hostBackupDownloadMarkerKey(), JSON.stringify({
      base: state.base, request_id: requestId, part, started_at: startedAt,
    }));
    const saved = hostBackupReadDownloadMarker();
    return saved?.requestId === requestId && saved.part === part &&
      saved.startedAt === startedAt ? saved : null;
  } catch { return null; }
}

function hostBackupClearDownloadMarker(pending) {
  try {
    const saved = hostBackupReadDownloadMarker();
    if (saved && saved.requestId === pending.requestId && saved.part === pending.part &&
        saved.startedAt === pending.startedAt)
      localStorage.removeItem(hostBackupDownloadMarkerKey());
    if (localStorage.getItem(hostBackupDownloadMarkerKey()) !== null) {
      hostBackupClient.portableDownloadPending = hostBackupReadDownloadMarker() || pending;
      return false;
    }
    hostBackupClient.portableDownloadPending = null;
    return true;
  } catch { return false; }
}

function hostBackupDate(value) {
  const stamp = Date.parse(value);
  if (typeof value !== "string" || value.length > 40 || !Number.isFinite(stamp) ||
      stamp < 0 || !/(?:Z|\+00:00)$/.test(value))
    throw new Error("Hub вернул неверную дату копии.");
  return new Date(stamp).toLocaleString("ru-RU", { timeZone: "UTC" }) + " UTC";
}

function hostBackupArchive(value, expectedId = null) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== 5 || !HOST_BACKUP_ID.test(value.id) ||
      (expectedId !== null && value.id !== expectedId) ||
      !["full", "hub-only"].includes(value.layout) ||
      !Number.isSafeInteger(value.bytes) || value.bytes < 1 ||
      value.bytes > 8 * 1024 ** 3 || !Number.isSafeInteger(value.files) ||
      value.files < 1 || value.files > 20000)
    throw new Error("Hub вернул неверное описание архива.");
  hostBackupDate(value.created_at);
  return value;
}

function hostBackupOperation(value, expectedId = null) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== 7 || value.ok !== true ||
      value.protocol !== "sovagrid-host-backup-operation-v1" ||
      !HOST_BACKUP_ID.test(value.request_id) ||
      (expectedId !== null && value.request_id !== expectedId) ||
      !Object.hasOwn(HOST_BACKUP_PHASES, value.phase) ||
      (value.archive !== null && !hostBackupArchive(value.archive)) ||
      (value.error !== null && (typeof value.error !== "string" ||
        !HOST_BACKUP_ERROR.test(value.error))))
    throw new Error("Hub вернул неверное состояние копирования хоста.");
  hostBackupDate(value.created_at);
  return value;
}

function hostBackupPortableReceipt(value, archiveId, layout = null) {
  const fields = ["protocol", "host_archive_id", "host_archive_sha256",
    "source_manifest_sha256", "images_sha256", "images", "container_ids",
    "exported_configs", "rootfs_sha256", "active_units", "unit_hashes"];
  const v2 = value?.protocol === HOST_PORTABLE_RECEIPT_V2;
  if (v2) fields.push("unit_states");
  const imageId = /^sha256:[0-9a-f]{64}$/;
  const matchingMap = (items, names, digest) => items && typeof items === "object" &&
    !Array.isArray(items) && Object.keys(items).length === names.length &&
    names.every((name) => Object.hasOwn(items, name) &&
      typeof items[name] === "string" && digest.test(items[name]));
  const imageNames = value?.images && typeof value.images === "object" &&
    !Array.isArray(value.images) ? Object.keys(value.images) : [];
  const units = Array.isArray(value?.active_units) ? value.active_units : [];
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== fields.length ||
      fields.some((field) => !Object.hasOwn(value, field)) ||
      ![HOST_PORTABLE_RECEIPT, HOST_PORTABLE_RECEIPT_V2].includes(value.protocol) ||
      value.host_archive_id !== archiveId ||
      !HOST_BACKUP_SHA.test(value.host_archive_sha256) ||
      !HOST_BACKUP_SHA.test(value.source_manifest_sha256) ||
      !HOST_BACKUP_SHA.test(value.images_sha256) ||
      !value.images || typeof value.images !== "object" || Array.isArray(value.images) ||
      ![2, 3].includes(Object.keys(value.images).length) ||
      !Object.hasOwn(value.images, "hub") || !Object.hasOwn(value.images, "web") ||
      Object.keys(value.images).some((name) => !["hub", "web", "ssh-gateway"].includes(name) ||
        typeof value.images[name] !== "string" ||
        !imageId.test(value.images[name])) ||
      !matchingMap(value.container_ids, imageNames, HOST_BACKUP_SHA) ||
      !matchingMap(value.rootfs_sha256, imageNames, HOST_BACKUP_SHA) ||
      !matchingMap(value.exported_configs, imageNames, imageId) ||
      !Array.isArray(value.active_units) || units.length > 32 ||
      new Set(units).size !== units.length ||
      units.some((unit) => typeof unit !== "string" ||
        !/^sovagrid-[a-z0-9_.@-]{1,80}\.(?:service|socket|timer)$/.test(unit)) ||
      !matchingMap(value.unit_hashes, units, HOST_BACKUP_SHA))
    throw new Error("Hub вернул неверную квитанцию переносимой копии.");
  if (v2) {
    const states = value.unit_states;
    const validLayout = typeof layout === "string" && Object.hasOwn(HOST_MANAGED_UNITS, layout);
    if (!validLayout || !states || typeof states !== "object" || Array.isArray(states) ||
        Object.keys(states).length > 32 ||
        Object.entries(states).some(([name, item]) => !HOST_MANAGED_UNITS[layout].has(name) ||
          !item || typeof item !== "object" || Array.isArray(item) ||
          Object.keys(item).length !== 3 ||
          !["active", "enablement", "sha256"].every((field) => Object.hasOwn(item, field)) ||
          typeof item.active !== "boolean" || typeof item.enablement !== "string" ||
          !HOST_UNIT_ENABLEMENT.has(item.enablement) || typeof item.sha256 !== "string" ||
          !HOST_BACKUP_SHA.test(item.sha256)) ||
        Object.keys(states).filter((name) => HOST_WRITER_UNITS[layout].has(name) &&
          states[name].active).length !== units.length ||
        units.some((name) => !Object.hasOwn(states, name) || !states[name].active ||
          !HOST_WRITER_UNITS[layout].has(name) || states[name].sha256 !== value.unit_hashes[name]) ||
        JSON.stringify(value).length + 1 > 8192)
      throw new Error("Hub вернул неверную квитанцию переносимой копии.");
  }
  return value;
}

function hostBackupPortableOperation(value, expectedId = null) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== 8 || !Object.hasOwn(value, "image_receipt"))
    throw new Error("Hub вернул неверное состояние переносимой копии.");
  const { image_receipt: receipt, ...ordinary } = value;
  const operation = hostBackupOperation(ordinary, expectedId);
  if ((operation.phase === "complete") !== (receipt !== null) ||
      (receipt !== null && (!operation.archive ||
        !hostBackupPortableReceipt(receipt, operation.archive.id, operation.archive.layout))))
    throw new Error("Hub вернул несогласованное состояние переносимой копии.");
  return { operation, receipt };
}

function hostBackupSameReceipt(left, right) {
  const ordered = (value) => Array.isArray(value) ? value.map(ordered) :
    value && typeof value === "object" ? Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, ordered(value[key])])) : value;
  return JSON.stringify(ordered(left)) === JSON.stringify(ordered(right));
}

function hostBackupPlan(value) {
  const plan = value?.plan;
  if (!plan || typeof plan !== "object" || Array.isArray(plan) ||
      !["full", "hub-only"].includes(plan.layout) ||
      !Array.isArray(plan.active_units) || plan.active_units.length > 32 ||
      plan.active_units.some((unit) => typeof unit !== "string" ||
        !/^sovagrid-[A-Za-z0-9_.@-]{1,96}\.(?:service|socket|timer)$/.test(unit)) ||
      !Array.isArray(plan.running_containers) || plan.running_containers.length > 2 ||
      plan.running_containers.some((item) => !["hub", "web"].includes(item)) ||
      new Set(plan.running_containers).size !== plan.running_containers.length ||
      typeof plan.offline_ready !== "boolean" ||
      !HOST_BACKUP_SHA.test(value.manifest_sha256))
    throw new Error("Hub вернул неверный план копирования хоста.");
  return { plan, manifest: value.manifest_sha256 };
}

function hostBackupSetActive(record, portable = false, receipt = null) {
  const client = hostBackupClient;
  const same = client.activeId === record.request_id && client.activePortable === portable &&
    client.active?.phase === record.phase &&
    client.active?.archive?.id === record.archive?.id &&
    (!portable || !receipt || (client.portableReceipt &&
      hostBackupSameReceipt(client.portableReceipt, receipt)));
  if (!same) {
    client.portableVerified = null;
    client.portableGrant = null;
  }
  client.activeId = record.request_id;
  client.active = record;
  client.activePortable = portable;
  client.portableReceipt = portable ? receipt || (same ? client.portableReceipt : null) : null;
  client.uncertain = false;
  if (HOST_BACKUP_FINAL.has(record.phase)) hostBackupClearMarker(record.request_id);
}

function hostBackupCanStart() {
  const client = hostBackupClient;
  return hubCanGlobalAdmin() && Boolean(state.token) && client.ready && client.plan &&
    client.manifest && !client.loading && !client.starting && !client.recovering &&
    !client.pending && !client.portableDownloadPending && !hostBackupReadDownloadMarker() &&
    !hostBackupReadMarker() &&
    !client.operations.some((item) => !HOST_BACKUP_FINAL.has(item.phase));
}

function hostBackupSameOrigin() {
  try { return new URL(state.base).origin === location.origin; }
  catch { return false; }
}

function hostBackupPortableCanStart() {
  return hostBackupCanStart() && hostBackupClient.portableAvailable;
}

function hostBackupRender() {
  const client = hostBackupClient;
  const ready = hubCanGlobalAdmin() && Boolean(state.token);
  $("hostBackupReload").disabled = !ready || client.loading || client.starting || client.recovering;
  $("hostBackupCreate").disabled = !hostBackupCanStart();
  $("hostBackupPortableCreate").disabled = !hostBackupPortableCanStart();
  $("hostBackupPortableSupport").textContent = client.portableAvailable
    ? "Переносимая копия включает архив хоста, точные образы контейнеров, два манифеста и квитанцию. После проверки скачайте все пять файлов."
    : "Переносимые копии появятся после установки совместимого серверного выпуска.";
  const downloadPending = $("hostBackupDownloadPending");
  downloadPending.replaceChildren();
  downloadPending.hidden = !ready || !client.portableDownloadPending;
  if (!downloadPending.hidden) {
    const pending = client.portableDownloadPending;
    const title = document.createElement("strong");
    title.textContent = `Скачивание «${HOST_PORTABLE_PARTS[pending.part]}» запрошено`;
    const detail = document.createElement("p");
    detail.textContent = `Запрос ${pending.requestId} · ${new Date(pending.startedAt).toLocaleString("ru-RU", { timeZone: "UTC" })} UTC. Сервер может проверять файлы до часа до начала передачи. После этого скачивание может идти дольше. Проверьте загрузки браузера: панель не видит, сохранён ли файл.`;
    const actions = document.createElement("div"); actions.className = "backup-card-actions";
    const complete = document.createElement("button"); complete.type = "button";
    complete.className = "primary-button"; complete.textContent = "Файл сохранён — продолжить";
    complete.addEventListener("click", () => { hostBackupResolveDownload("complete"); });
    const retry = document.createElement("button"); retry.type = "button";
    retry.className = "secondary-button";
    retry.textContent = "Скачивание прервалось — повторить…";
    retry.addEventListener("click", hostBackupPrepareDownloadRetry);
    actions.append(complete, retry);
    downloadPending.append(title, detail, actions);
  }
  $("hostBackupCount").textContent = client.ready ? String(client.archives.length) : "—";
  $("hostBackupPlan").textContent = client.plan
    ? `${client.plan.layout === "full" ? "Полный узел" : "Только Hub"} · ${client.plan.active_units.length} служб · ${client.plan.running_containers.length} контейнера(ов). При создании архивируются настройки и данные этого узла.`
    : "План ещё не получен.";
  const active = $("hostBackupActive"); active.replaceChildren();
  active.hidden = !client.activeId;
  if (client.activeId) {
    const title = document.createElement("strong");
    title.textContent = client.active ? `${HOST_BACKUP_PHASES[client.active.phase]} · ${client.activeId}`
      : `Запрос ${client.activeId}: ожидаем подтверждение сервера`;
    const info = document.createElement("p");
    info.textContent = client.active
      ? [`Начало: ${hostBackupDate(client.active.created_at)}`,
        client.active.archive ? `Архив: ${client.active.archive.id} · ${bytes(client.active.archive.bytes)}` : null,
        client.active.error ? `Код: ${client.active.error}` : null].filter(Boolean).join(" · ")
      : "После восстановления связи проверьте этот ID. Не запускайте повторно копирование.";
    const actions = document.createElement("div"); actions.className = "backup-card-actions";
    const check = document.createElement("button"); check.type = "button";
    check.className = "secondary-button"; check.textContent = "Проверить состояние";
    check.disabled = !ready || Boolean(client.checking) || client.starting || client.recovering;
    check.addEventListener("click", () => { void (client.activePortable
      ? hostBackupPortableCheck(client.activeId) : hostBackupCheck(client.activeId)); });
    actions.append(check);
    if (client.activePortable && client.active?.phase === "complete" && client.portableReceipt) {
      const verify = document.createElement("button"); verify.type = "button";
      verify.className = "secondary-button";
      verify.textContent = client.checking === client.activeId ? "Проверяем…" :
        "Проверить архив и образы";
      verify.disabled = !ready || Boolean(client.portableDownloadPending) ||
        Boolean(client.checking) || client.starting || client.recovering;
      verify.addEventListener("click", () => { void hostBackupPortableVerify(client.activeId); });
      actions.append(verify);
    }
    if (client.active && !HOST_BACKUP_FINAL.has(client.active.phase)) {
      const recover = document.createElement("button"); recover.type = "button";
      recover.className = "secondary-button"; recover.textContent = "Восстановить службы…";
      recover.disabled = !ready || Boolean(client.checking) || client.starting || client.recovering;
      recover.addEventListener("click", () => hostBackupPrepareRecover(client.activeId));
      actions.append(recover);
    }
    active.append(title, info, actions);
  }
  const portableFiles = $("hostBackupPortableFiles"); portableFiles.replaceChildren();
  portableFiles.hidden = !(client.portableVerified && client.activePortable &&
    client.activeId === client.portableVerified.requestId);
  if (!portableFiles.hidden) {
    const result = client.portableVerified;
    const summary = document.createElement("p");
    summary.textContent = `Пара проверена: архив ${bytes(result.archive.bytes)}, образы ${bytes(result.imagesBytes)}. Скачайте все пять файлов. На целевом сервере положите архив и его манифест рядом, а образы, их манифест и квитанцию — в каталог ${result.archive.id}/. Файлы содержат секреты сервера.`;
    portableFiles.append(summary);
    if (!hostBackupSameOrigin()) {
      const notice = document.createElement("p");
      notice.textContent = "Для скачивания откройте веб-панель самого выбранного Hub и войдите там. Файлы не пересылаются через этот сайт.";
      const link = document.createElement("a");
      link.textContent = "Открыть панель выбранного Hub";
      link.href = new URL("/sovagrid/monitoring/", state.base).href;
      link.target = "_blank"; link.rel = "noopener noreferrer";
      portableFiles.append(notice, link);
    } else {
      const list = document.createElement("div"); list.className = "host-portable-files";
      for (const [part, label] of Object.entries(HOST_PORTABLE_PARTS)) {
        const row = document.createElement("div"); row.className = "host-portable-file";
        const name = document.createElement("span");
        name.textContent = `${label} — ${hostBackupPortableStagePath(part, result.archive.id)}`;
        const grant = client.portableGrant;
        const pendingThis = client.portableDownloadPending?.requestId === result.requestId &&
          client.portableDownloadPending.part === part;
        if (pendingThis) {
          const status = document.createElement("span");
          status.className = "field-help"; status.textContent = "Ожидаем браузер";
          row.append(name, status);
        } else if (grant && grant.requestId === result.requestId && grant.part === part &&
            grant.expiresAt > Date.now() && grant.base === state.base && grant.token === state.token) {
          const link = document.createElement("a");
          link.className = "secondary-button";
          link.textContent = "Скачать";
          link.href = `${state.base}/api/v1/host-backups/operations/${result.requestId}/portable/download/${part}`;
          link.download = hostBackupPortableFilename(part, result.archive.id);
          link.addEventListener("click", (event) => {
            const pending = hostBackupSaveDownloadMarker(result.requestId, part);
            if (!pending) {
              event.preventDefault();
              showError($("hostBackupError"),
                "Не удалось сохранить состояние скачивания или уже идёт другая загрузка. Разрешите хранение данных сайта и обновите панель.");
              return;
            }
            client.portableDownloadPending = pending;
            client.portableGrant = null;
            link.setAttribute("aria-disabled", "true");
            link.style.pointerEvents = "none";
            $("hostBackupStatus").textContent =
              "Запрос на скачивание отправлен. Проверка на сервере может занять до часа; следите за загрузками браузера.";
            const redraw = setTimeout(() => {
              if (hostBackupCurrent(client.generation, state.token, state.base))
                hostBackupRender();
            }, 1500);
            redraw?.unref?.();
          });
          row.append(name, link);
        } else {
          const prepare = document.createElement("button"); prepare.type = "button";
          prepare.className = "secondary-button";
          prepare.textContent = "Подготовить скачивание";
          prepare.disabled = !ready || Boolean(client.portableDownloadPending) ||
            Boolean(client.checking) || client.starting || client.recovering;
          prepare.addEventListener("click", () => { void hostBackupPortablePrepareDownload(result.requestId, part); });
          row.append(name, prepare);
        }
        list.append(row);
      }
      portableFiles.append(list);
      const note = document.createElement("p"); note.className = "field-help";
      note.textContent = "Нажмите «Подготовить скачивание», затем «Скачать» в течение минуты. Сервер может проверять файлы до часа перед передачей. Дождитесь результата в загрузках браузера и подтвердите его выше; SovaGrid не загружает многогигабайтный архив в память страницы.";
      portableFiles.append(note);
    }
  }
  const archives = $("hostBackupArchives"); archives.replaceChildren();
  if (client.ready && !client.archives.length) {
    const empty = document.createElement("p"); empty.className = "no-incidents";
    empty.textContent = "Архивов хоста пока нет."; archives.append(empty);
  }
  for (const item of client.archives) {
    const card = document.createElement("article"); card.className = "backup-card";
    const content = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = `${hostBackupDate(item.created_at)} · ${item.layout === "full" ? "полный узел" : "Hub"}`;
    const info = document.createElement("p");
    info.textContent = `${bytes(item.bytes)} · ${item.files} файлов · ID ${item.id}`;
    const action = document.createElement("button"); action.type = "button";
    action.className = "secondary-button";
    action.textContent = client.checking === item.id ? "Проверяем…" : "Проверить целостность";
    action.disabled = !ready || Boolean(client.checking) || client.starting || client.recovering;
    action.addEventListener("click", () => { void hostBackupVerify(item.id); });
    content.append(title, info); card.append(content, action); archives.append(card);
  }
  const operations = $("hostBackupOperations"); operations.replaceChildren();
  for (const item of client.operations.slice(0, 20)) {
    const card = document.createElement("article"); card.className = "backup-card";
    const content = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = `${HOST_BACKUP_PHASES[item.phase]} · ${hostBackupDate(item.created_at)}`;
    const info = document.createElement("p");
    info.textContent = `Запрос ${item.request_id}${item.error ? " · код " + item.error : ""}`;
    const action = document.createElement("button"); action.type = "button";
    action.className = "secondary-button"; action.textContent = "Состояние";
    action.disabled = !ready || Boolean(client.checking) || client.starting || client.recovering;
    action.addEventListener("click", () => { void hostBackupCheck(item.request_id); });
    content.append(title, info); card.append(content, action);
    if (client.portableAvailable && item.phase === "complete") {
      const portable = document.createElement("button"); portable.type = "button";
      portable.className = "secondary-button"; portable.textContent = "Проверить переносимую копию";
      portable.disabled = !ready || Boolean(client.checking) || client.starting || client.recovering;
      portable.addEventListener("click", () => { void hostBackupPortableCheck(item.request_id); });
      card.append(portable);
    }
    operations.append(card);
  }
}

function hostBackupsReset() {
  hostBackupClient.generation++;
  Object.assign(hostBackupClient, { loading: false, checking: null, starting: false,
    recovering: false, plan: null, manifest: null, archives: [], operations: [],
    activeId: null, active: null, pending: null, pendingRecover: null,
    lastRefresh: 0, ready: false, uncertain: false, portableAvailable: false,
    activePortable: false, portableReceipt: null, portableVerified: null,
    portableGrant: null, portableDownloadPending: null });
  if ($("hostBackupCreateDialog").open) $("hostBackupCreateDialog").close();
  if ($("hostBackupRecoverDialog").open) $("hostBackupRecoverDialog").close();
  if ($("hostBackupDownloadRetryDialog").open) $("hostBackupDownloadRetryDialog").close();
  $("hostBackupStatus").textContent = "Откройте настройки, чтобы проверить копии хоста.";
  clearError($("hostBackupError"));
  hostBackupRender();
}
globalThis.hostBackupsReset = hostBackupsReset;

async function hostBackupsRefresh(force = false) {
  if (!state.token || !hubCanGlobalAdmin() || hostBackupClient.loading ||
      hostBackupClient.starting || hostBackupClient.recovering) return;
  const client = hostBackupClient;
  const interval = hostBackupReadMarker() || client.operations.some((item) =>
    !HOST_BACKUP_FINAL.has(item.phase)) ? 15000 : 45000;
  if (!force && Date.now() - client.lastRefresh < interval) return;
  const generation = client.generation, token = state.token, base = state.base;
  client.loading = true; client.lastRefresh = Date.now();
  client.portableDownloadPending = hostBackupReadDownloadMarker();
  const markerRecord = hostBackupReadMarkerRecord();
  const marker = markerRecord?.requestId || null;
  if (marker && !client.activeId) client.activeId = marker;
  hostBackupRender();
  const [planResult, archivesResult, operationsResult, portableResult] = await Promise.allSettled([
    request("/api/v1/host-backups/plan", { timeoutMs: 20000 }),
    request("/api/v1/host-backups/archives", { timeoutMs: 20000 }),
    request("/api/v1/host-backups/operations", { timeoutMs: 20000 }),
    request("/api/v1/host-backups/portable/capabilities", { timeoutMs: 20000 }),
  ]);
  if (!hostBackupCurrent(generation, token, base)) return;
  const errors = [];
  client.portableAvailable = portableResult.status === "fulfilled" &&
    portableResult.value?.supported === true && portableResult.value?.download === true;
  if (planResult.status === "fulfilled") {
    try {
      const parsed = hostBackupPlan(planResult.value);
      client.plan = parsed.plan; client.manifest = parsed.manifest;
    } catch (error) { client.plan = null; client.manifest = null; errors.push(error.message); }
  } else {
    client.plan = null; client.manifest = null;
    errors.push(planResult.reason?.status === 404 ? "Обновите Hub для копий хоста." :
      "План хоста недоступен.");
  }
  if (archivesResult.status === "fulfilled") {
    try {
      const items = archivesResult.value?.archives;
      if (!Array.isArray(items) || items.length > 100) throw new Error("Неверный список архивов.");
      const parsed = items.map((item) => hostBackupArchive(item));
      if (new Set(parsed.map((item) => item.id)).size !== parsed.length)
        throw new Error("Повторяющиеся архивы.");
      client.archives = parsed;
    } catch (error) { client.archives = []; errors.push(error.message); }
  } else { client.archives = []; errors.push("Список архивов недоступен."); }
  if (operationsResult.status === "fulfilled") {
    try {
      const items = operationsResult.value?.operations;
      if (!Array.isArray(items) || items.length > 100)
        throw new Error("Неверная история операций.");
      const parsed = items.map((item) => hostBackupOperation(item));
      if (new Set(parsed.map((item) => item.request_id)).size !== parsed.length)
        throw new Error("Повторяющиеся операции.");
      client.operations = parsed;
      const selected = parsed.find((item) => item.request_id === (marker || client.activeId));
      if (selected) hostBackupSetActive(selected,
        selected.request_id === marker ? markerRecord?.mode === "portable" :
          client.activePortable);
    } catch (error) { client.operations = []; errors.push(error.message); }
  } else { client.operations = []; errors.push("История операций недоступна."); }
  client.ready = errors.length === 0;
  client.loading = false;
  if (marker && !client.operations.some((item) => item.request_id === marker)) {
    try {
      const portable = markerRecord?.mode === "portable";
      const raw = await request(`/api/v1/host-backups/operations/${marker}` +
        (portable ? "/portable" : ""), { timeoutMs: 20000 });
      const parsed = portable ? hostBackupPortableOperation(raw, marker) :
        { operation: hostBackupOperation(raw, marker), receipt: null };
      if (!hostBackupCurrent(generation, token, base)) return;
      hostBackupSetActive(parsed.operation, portable, parsed.receipt);
    } catch {
      if (hostBackupCurrent(generation, token, base)) client.uncertain = true;
    }
  } else if (marker && markerRecord?.mode === "portable") {
    try {
      const parsed = hostBackupPortableOperation(await request(
        `/api/v1/host-backups/operations/${marker}/portable`, { timeoutMs: 20000 }), marker);
      if (!hostBackupCurrent(generation, token, base)) return;
      hostBackupSetActive(parsed.operation, true, parsed.receipt);
    } catch {
      if (hostBackupCurrent(generation, token, base)) client.uncertain = true;
    }
  }
  if (!hostBackupCurrent(generation, token, base)) return;
  $("hostBackupStatus").textContent = client.uncertain
    ? `Запрос ${client.activeId || marker} сохранён. Hub мог перезапуститься; проверьте состояние после входа.`
    : `Архивов: ${client.archives.length}. Запросов: ${client.operations.length}.`;
  if (errors.length) showError($("hostBackupError"), errors.join(" "));
  else clearError($("hostBackupError"));
  hostBackupRender();
}
globalThis.hostBackupsRefresh = hostBackupsRefresh;

async function hostBackupCheck(requestId) {
  if (!HOST_BACKUP_ID.test(requestId) || !state.token || !hubCanGlobalAdmin() ||
      hostBackupClient.checking || hostBackupClient.starting || hostBackupClient.recovering) return;
  const client = hostBackupClient, generation = client.generation,
    token = state.token, base = state.base;
  client.activeId = requestId; client.checking = requestId; hostBackupRender();
  try {
    const record = hostBackupOperation(await request(
      `/api/v1/host-backups/operations/${requestId}`, { timeoutMs: 30000 }), requestId);
    if (!hostBackupCurrent(generation, token, base)) return;
    hostBackupSetActive(record);
    $("hostBackupStatus").textContent = `Запрос ${requestId}: ${HOST_BACKUP_PHASES[record.phase]}.`;
    clearError($("hostBackupError"));
  } catch {
    if (hostBackupCurrent(generation, token, base)) {
      client.uncertain = true;
      showError($("hostBackupError"), `Состояние запроса ${requestId} пока недоступно. Не запускайте повторное копирование. При остановленном Hub используйте Connect по SSH.`);
    }
  } finally {
    if (hostBackupCurrent(generation, token, base)) { client.checking = null; hostBackupRender(); }
  }
}

async function hostBackupVerify(archiveId) {
  if (!HOST_BACKUP_ID.test(archiveId) || !hostBackupClient.archives.some((item) =>
    item.id === archiveId) || !state.token || !hubCanGlobalAdmin() ||
      hostBackupClient.checking || hostBackupClient.starting || hostBackupClient.recovering) return;
  const client = hostBackupClient, generation = client.generation,
    token = state.token, base = state.base;
  client.checking = archiveId; hostBackupRender();
  $("hostBackupStatus").textContent = "Проверяем архив; это может занять несколько минут…";
  try {
    const result = await request(
      `/api/v1/host-backups/archives/${archiveId}/verify`, { timeoutMs: 360000 });
    if (!hostBackupCurrent(generation, token, base)) return;
    if (result?.verified !== true) throw new Error("Проверка архива не подтверждена.");
    const archive = hostBackupArchive(result.archive, archiveId);
    $("hostBackupStatus").textContent = `Архив ${archive.id} проверен: ${bytes(archive.bytes)}, ${archive.files} файлов.`;
    clearError($("hostBackupError"));
  } catch (error) {
    if (hostBackupCurrent(generation, token, base))
      showError($("hostBackupError"), error.message || "Архив не удалось проверить.");
  } finally {
    if (hostBackupCurrent(generation, token, base)) { client.checking = null; hostBackupRender(); }
  }
}

async function hostBackupPortableCheck(requestId) {
  if (!HOST_BACKUP_ID.test(requestId) || !state.token || !hubCanGlobalAdmin() ||
      hostBackupClient.checking || hostBackupClient.starting || hostBackupClient.recovering) return;
  const client = hostBackupClient, generation = client.generation,
    token = state.token, base = state.base;
  client.checking = requestId; hostBackupRender();
  try {
    const parsed = hostBackupPortableOperation(await request(
      `/api/v1/host-backups/operations/${requestId}/portable`, { timeoutMs: 30000 }), requestId);
    if (!hostBackupCurrent(generation, token, base)) return;
    hostBackupSetActive(parsed.operation, true, parsed.receipt);
    $("hostBackupStatus").textContent = parsed.operation.phase === "complete"
      ? "Переносимая копия создана. Проверьте архив и образы перед скачиванием."
      : `Переносимая копия: ${HOST_BACKUP_PHASES[parsed.operation.phase]}.`;
    clearError($("hostBackupError"));
  } catch (error) {
    if (hostBackupCurrent(generation, token, base))
      showError($("hostBackupError"), error.status === 404 || error.status === 409
        ? "Это задание не содержит переносимую копию или больше недоступно."
        : error.message || "Не удалось проверить переносимую копию.");
  } finally {
    if (hostBackupCurrent(generation, token, base)) { client.checking = null; hostBackupRender(); }
  }
}

async function hostBackupPortableVerify(requestId) {
  const client = hostBackupClient;
  if (!HOST_BACKUP_ID.test(requestId) || client.activeId !== requestId ||
      !client.activePortable || client.active?.phase !== "complete" ||
      !client.portableReceipt || !state.token || !hubCanGlobalAdmin() ||
      client.portableDownloadPending || client.checking || client.starting || client.recovering) return;
  const generation = client.generation, token = state.token, base = state.base;
  client.checking = requestId; client.portableVerified = null; client.portableGrant = null;
  hostBackupRender();
  $("hostBackupStatus").textContent = "Проверяем архив и образы на сервере; это может занять несколько минут…";
  try {
    const result = await request(
      `/api/v1/host-backups/operations/${requestId}/portable/verify`,
      { timeoutMs: 2700000 });
    if (!hostBackupCurrent(generation, token, base)) return;
    if (!result || Object.keys(result).sort().join(",") !==
        "archive,images_bytes,ok,receipt,request_id" || result.ok !== true ||
        result.request_id !== requestId ||
        !Number.isSafeInteger(result.images_bytes) || result.images_bytes < 1 ||
        result.images_bytes > 8 * 1024 ** 3)
      throw new Error("Hub вернул неверный результат проверки переносимой копии.");
    const archive = hostBackupArchive(result.archive, client.active.archive.id);
    const receipt = hostBackupPortableReceipt(result.receipt, archive.id, archive.layout);
    if (archive.bytes !== client.active.archive.bytes ||
        !hostBackupSameReceipt(receipt, client.portableReceipt))
      throw new Error("Архив и квитанция изменились после проверки состояния.");
    client.portableVerified = { requestId, archive, imagesBytes: result.images_bytes,
      receipt, base, token };
    $("hostBackupStatus").textContent = "Пара проверена. Подготовьте скачивание каждого из пяти файлов.";
    clearError($("hostBackupError"));
  } catch (error) {
    if (hostBackupCurrent(generation, token, base))
      showError($("hostBackupError"), error.message || "Пару не удалось проверить.");
  } finally {
    if (hostBackupCurrent(generation, token, base)) { client.checking = null; hostBackupRender(); }
  }
}

async function hostBackupPortablePrepareDownload(requestId, part) {
  const client = hostBackupClient, verified = client.portableVerified;
  const savedDownload = hostBackupReadDownloadMarker();
  if (savedDownload && !client.portableDownloadPending) {
    client.portableDownloadPending = savedDownload;
    hostBackupRender();
  }
  if (!HOST_BACKUP_ID.test(requestId) || !Object.hasOwn(HOST_PORTABLE_PARTS, part) ||
      !verified || verified.requestId !== requestId || verified.base !== state.base ||
      verified.token !== state.token || !hostBackupSameOrigin() ||
      client.portableDownloadPending ||
      !hubCanGlobalAdmin() || client.checking || client.starting || client.recovering) return;
  const generation = client.generation, token = state.token, base = state.base;
  client.checking = requestId; client.portableGrant = null; hostBackupRender();
  try {
    const grant = await request(
      `/api/v1/host-backups/operations/${requestId}/portable/download-grants/${part}`,
      { method: "POST", body: "{}", timeoutMs: 120000 });
    if (!hostBackupCurrent(generation, token, base)) return;
    if (!grant || Object.keys(grant).sort().join(",") !==
        "expires_in_seconds,part,request_id" ||
        grant.request_id !== requestId || grant.part !== part ||
        !Number.isSafeInteger(grant.expires_in_seconds) ||
        grant.expires_in_seconds < 1 || grant.expires_in_seconds > 60)
      throw new Error("Hub не подтвердил одноразовое скачивание.");
    client.portableGrant = { requestId, part, base, token,
      expiresAt: Date.now() + grant.expires_in_seconds * 1000 };
    $("hostBackupStatus").textContent = `Разрешение для «${HOST_PORTABLE_PARTS[part]}» готово на ${grant.expires_in_seconds} секунд. Нажмите «Скачать».`;
    clearError($("hostBackupError"));
    const timer = setTimeout(() => {
      if (client.portableGrant?.requestId === requestId &&
          client.portableGrant.part === part && client.portableGrant.expiresAt <= Date.now()) {
        client.portableGrant = null;
        if (hostBackupCurrent(generation, token, base)) hostBackupRender();
      }
    }, grant.expires_in_seconds * 1000 + 50);
    timer?.unref?.(); // Node UI tests; browsers return a numeric timer ID.
  } catch (error) {
    if (hostBackupCurrent(generation, token, base))
      showError($("hostBackupError"), error.message || "Не удалось подготовить скачивание.");
  } finally {
    if (hostBackupCurrent(generation, token, base)) { client.checking = null; hostBackupRender(); }
  }
}

function hostBackupPrepareDownloadRetry() {
  const pending = hostBackupClient.portableDownloadPending;
  if (!pending || !hubCanGlobalAdmin() || !state.token) return;
  $("hostBackupDownloadRetrySummary").textContent =
    `«${HOST_PORTABLE_PARTS[pending.part]}» · запрос ${pending.requestId}. Повторите только если браузер показал ошибку, вы остановили прежнюю загрузку или она так и не появилась после долгого ожидания. Панель не может проверить завершение загрузки. После подтверждения подготовьте новое скачивание.`;
  $("hostBackupDownloadRetryDialog").showModal();
}

function hostBackupResolveDownload(outcome) {
  if (!["complete", "retry"].includes(outcome)) return;
  const pending = hostBackupClient.portableDownloadPending;
  if (!pending || !hubCanGlobalAdmin() || !state.token) return;
  if ($("hostBackupDownloadRetryDialog").open) $("hostBackupDownloadRetryDialog").close();
  if (!hostBackupClearDownloadMarker(pending)) {
    showError($("hostBackupError"),
      "Не удалось убрать локальную запись о скачивании. Проверьте разрешение на хранение данных сайта и обновите панель.");
    hostBackupRender();
    return;
  }
  hostBackupClient.portableGrant = null;
  if (outcome === "retry") hostBackupClient.portableVerified = null;
  $("hostBackupStatus").textContent = outcome === "complete"
    ? `«${HOST_PORTABLE_PARTS[pending.part]}» сохранён. Можно скачать следующий файл.`
    : "Прежняя попытка отмечена как прерванная. Проверьте архив и образы, затем подготовьте новое скачивание.";
  clearError($("hostBackupError"));
  hostBackupRender();
}

async function hostBackupPrepareCreate(mode = "ordinary") {
  if (mode !== "ordinary" && mode !== "portable") return;
  if (mode === "portable" ? !hostBackupPortableCanStart() : !hostBackupCanStart()) return;
  const client = hostBackupClient, generation = client.generation,
    token = state.token, base = state.base;
  client.loading = true; hostBackupRender();
  try {
    const fresh = hostBackupPlan(await request(
      "/api/v1/host-backups/plan", { timeoutMs: 20000 }));
    if (!hostBackupCurrent(generation, token, base)) return;
    if (fresh.manifest !== client.manifest || fresh.plan.layout !== client.plan.layout)
      throw new Error("Состояние хоста изменилось. Обновите план и подтвердите заново.");
    const requestId = crypto.randomUUID().replaceAll("-", "");
    if (!HOST_BACKUP_ID.test(requestId)) throw new Error("Не удалось создать ID запроса.");
    client.pending = { requestId, manifest: fresh.manifest, plan: fresh.plan,
      generation, token, base, mode };
    $("hostBackupCreateHeading").textContent = mode === "portable"
      ? "Создать переносимую копию?" : "Временно остановить службы?";
    $("hostBackupCreateConfirm").textContent = mode === "portable"
      ? "Создать переносимую копию" : "Остановить и создать копию";
    $("hostBackupCreateSummary").textContent =
      `Режим: ${fresh.plan.layout === "full" ? "полный узел" : "только Hub"}\n` +
      `Активных служб: ${fresh.plan.active_units.length}; контейнеров: ${fresh.plan.running_containers.length}.\n` +
      (mode === "portable" ?
        "Будет создан архив данных, точные образы контейнеров и квитанция. " : "") +
      `Службы и панель временно остановятся. ID запроса: ${requestId}.`;
    clearError($("hostBackupCreateError"));
    $("hostBackupCreateDialog").showModal();
  } catch (error) {
    if (hostBackupCurrent(generation, token, base))
      showError($("hostBackupError"), error.message || "Не удалось проверить план.");
  } finally {
    if (hostBackupCurrent(generation, token, base)) { client.loading = false; hostBackupRender(); }
  }
}

async function hostBackupConfirmCreate() {
  const client = hostBackupClient, pending = client.pending;
  if (!pending || !hostBackupCurrent(pending.generation, pending.token, pending.base) ||
      client.starting || client.recovering || hostBackupReadMarker() ||
      client.portableDownloadPending || hostBackupReadDownloadMarker() ||
      client.operations.some((item) => !HOST_BACKUP_FINAL.has(item.phase))) return;
  if (!hostBackupSaveMarker(pending.requestId, pending.mode)) {
    showError($("hostBackupCreateError"),
      "Браузер не сохранил ID запроса. Разрешите хранение данных для сайта или создайте копию через Connect.");
    return;
  }
  client.pending = null; $("hostBackupCreateDialog").close();
  client.starting = true; client.activeId = pending.requestId; client.active = null;
  client.activePortable = pending.mode === "portable";
  client.portableReceipt = null; client.portableVerified = null; client.portableGrant = null;
  client.uncertain = true; hostBackupRender();
  $("hostBackupStatus").textContent = pending.mode === "portable"
    ? "Создание переносимой копии запущено. Панель временно потеряет связь; ID сохранён."
    : "Создание копии запущено. Панель временно потеряет связь; ID запроса сохранён.";
  try {
    const endpoint = pending.mode === "portable" ?
      "/api/v1/host-backups/portable/operations" : "/api/v1/host-backups/operations";
    const record = hostBackupOperation(await request(endpoint, {
      method: "POST", body: JSON.stringify({ request_id: pending.requestId,
        expected_manifest_sha256: pending.manifest }), timeoutMs: 30000,
    }), pending.requestId);
    if (!hostBackupCurrent(pending.generation, pending.token, pending.base)) return;
    hostBackupSetActive(record, pending.mode === "portable");
  } catch {
    if (hostBackupCurrent(pending.generation, pending.token, pending.base))
      showError($("hostBackupError"), `Ответ на запрос ${pending.requestId} потерян или отклонён. Не запускайте копирование повторно; проверьте сохранённый ID после восстановления связи.`);
  } finally {
    if (hostBackupCurrent(pending.generation, pending.token, pending.base)) {
      client.starting = false; hostBackupRender();
      void hostBackupsRefresh(true);
    }
  }
}

function hostBackupPrepareRecover(requestId) {
  const client = hostBackupClient, active = client.active;
  if (!active || active.request_id !== requestId || HOST_BACKUP_FINAL.has(active.phase) ||
      !state.token || !hubCanGlobalAdmin() || client.starting || client.recovering) return;
  client.pendingRecover = requestId;
  $("hostBackupRecoverSummary").textContent = `Запрос: ${requestId}\nСостояние: ${HOST_BACKUP_PHASES[active.phase]}.\nИсправление восстановит ранее запущенные службы и не создаст архив повторно.`;
  clearError($("hostBackupRecoverError"));
  $("hostBackupRecoverDialog").showModal();
}

async function hostBackupConfirmRecover() {
  const client = hostBackupClient, requestId = client.pendingRecover;
  if (!requestId || !HOST_BACKUP_ID.test(requestId) || !state.token ||
      !hubCanGlobalAdmin() || client.starting || client.recovering) return;
  if (!hostBackupSaveMarker(requestId)) {
    showError($("hostBackupRecoverError"), "Браузер не сохранил ID. Исправьте сбой через Connect по SSH.");
    return;
  }
  client.pendingRecover = null; $("hostBackupRecoverDialog").close();
  const generation = client.generation, token = state.token, base = state.base;
  client.recovering = true; client.uncertain = true; hostBackupRender();
  try {
    const record = hostBackupOperation(await request(
      `/api/v1/host-backups/operations/${requestId}/recover`,
      { method: "POST", body: "{}", timeoutMs: 30000 }), requestId);
    if (!hostBackupCurrent(generation, token, base)) return;
    hostBackupSetActive(record, client.activePortable && client.activeId === requestId);
    $("hostBackupStatus").textContent = `Запрос ${requestId}: ${HOST_BACKUP_PHASES[record.phase]}.`;
  } catch {
    if (hostBackupCurrent(generation, token, base))
      showError($("hostBackupError"), `Ответ исправления по запросу ${requestId} потерян или отклонён. Проверьте статус; при остановленном Hub используйте Connect по SSH.`);
  } finally {
    if (hostBackupCurrent(generation, token, base)) {
      client.recovering = false; hostBackupRender(); void hostBackupsRefresh(true);
    }
  }
}

$("hostBackupReload").addEventListener("click", () => { void hostBackupsRefresh(true); });
$("hostBackupCreate").addEventListener("click", () => { void hostBackupPrepareCreate("ordinary"); });
$("hostBackupPortableCreate").addEventListener("click", () => { void hostBackupPrepareCreate("portable"); });
$("hostBackupDownloadRetryCancel").addEventListener("click", () => $("hostBackupDownloadRetryDialog").close());
$("hostBackupDownloadRetryConfirm").addEventListener("click", () => hostBackupResolveDownload("retry"));
$("hostBackupCreateConfirm").addEventListener("click", () => { void hostBackupConfirmCreate(); });
$("hostBackupCreateCancel").addEventListener("click", () => $("hostBackupCreateDialog").close());
$("hostBackupCreateDialog").addEventListener("close", () => { hostBackupClient.pending = null; hostBackupRender(); });
$("hostBackupRecoverConfirm").addEventListener("click", () => { void hostBackupConfirmRecover(); });
$("hostBackupRecoverCancel").addEventListener("click", () => $("hostBackupRecoverDialog").close());
$("hostBackupRecoverDialog").addEventListener("close", () => { hostBackupClient.pendingRecover = null; });
globalThis.addEventListener?.("storage", (event) => {
  if (event.key !== hostBackupDownloadMarkerKey() || !state.token) return;
  hostBackupClient.portableDownloadPending = hostBackupReadDownloadMarker();
  hostBackupClient.portableGrant = null;
  hostBackupRender();
});

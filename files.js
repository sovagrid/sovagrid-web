/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// This state belongs to the current tab only. File bytes never enter localStorage.
const BINARY_FILE_LIMIT = 4 * 1024 * 1024;
const BINARY_DOWNLOAD_LIMIT = 32 * 1024 * 1024;
const BINARY_CHUNK_SIZE = 64 * 1024;
const MAX_OUTSTANDING_DOWNLOAD_URLS = 2;
const filesClient = { generation: 0, serverId: null, roots: [], root: "", path: "",
  filePath: "", etag: "", originalText: "", busy: false, loaded: false,
  pendingSave: null, pendingTransfer: null, transfer: null, downloadUrls: new Set(),
  lastEntries: [], truncated: false };

const FILE_ERRORS = {
  disabled: "Доступ к файлам выключен в конфигурации Agent.",
  unknown_root: "Разрешённый каталог больше не существует на Agent.",
  not_found: "Файл или каталог не найден. Обновите список.",
  unsupported: "Можно работать только с обычным файлом без ссылок.",
  too_large: "Файл превышает лимит: 8 КБ для редактора, 32 МБ для скачивания или 4 МБ для загрузки.",
  conflict: "Файл изменился на сервере. Обновите список перед повтором; несохранённый текст остался в редакторе.",
  denied: "У Agent нет прав на этот файл или каталог.",
  unavailable: "Файловая операция недоступна на Agent.",
  busy: "На Agent уже выполняется слишком много передач. Повторите позже.",
  invalid_path: "Недопустимый путь к файлу.",
  invalid_content: "Содержимое файла имеет неверный формат.",
};

function filesReset() {
  filesClient.generation++;
  filesClient.serverId = null;
  filesClient.roots = [];
  filesClient.root = "";
  filesClient.path = "";
  filesClient.filePath = "";
  filesClient.etag = "";
  filesClient.originalText = "";
  filesClient.busy = false;
  filesClient.loaded = false;
  filesClient.pendingSave = null;
  filesClient.pendingTransfer = null;
  if (filesClient.transfer) filesClient.transfer.cancelled = true;
  filesClient.transfer = null;
  for (const url of filesClient.downloadUrls) URL.revokeObjectURL(url);
  filesClient.downloadUrls.clear();
  filesClient.lastEntries = [];
  filesClient.truncated = false;
  $("filesText").value = "";
  $("filesText").disabled = true;
  $("filesRoot").replaceChildren();
  $("filesEntries").replaceChildren();
  $("filesPath").textContent = "/";
  $("filesCurrentFile").textContent = "Откройте текстовый файл из списка.";
  $("filesEditorState").textContent = "Файл не открыт";
  $("filesStatus").textContent = "Не подключено";
  clearError($("filesError"));
  clearError($("filesSaveError"));
  clearError($("filesTransferError"));
  $("filesTransferStatus").textContent = "";
  $("filesUploadInput").value = "";
  if ($("filesSaveDialog").open) $("filesSaveDialog").close();
  if ($("filesTransferDialog").open) $("filesTransferDialog").close();
  renderFilesButtons();
}
globalThis.filesReset = filesReset;

function filesCurrent(generation, serverId, token, base) {
  return filesClient.generation === generation && filesClient.serverId === serverId &&
    state.selectedId === serverId && state.token === token && state.base === base && Boolean(token);
}

function filesError(code) {
  return FILE_ERRORS[code] || "Файловая операция завершилась ошибкой.";
}

async function fileOperation(payload, idempotencyKey = crypto.randomUUID()) {
  const serverId = filesClient.serverId, generation = filesClient.generation;
  const token = state.token, base = state.base;
  const ensureCurrent = () => {
    if (!filesCurrent(generation, serverId, token, base)) throw new Error("Сервер или сеанс изменился.");
  };
  ensureCurrent();
  const path = `/api/v1/servers/${encodeURIComponent(serverId)}/files/operations`;
  let created;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      created = await request(path, { method: "POST", headers: { "Idempotency-Key": idempotencyKey },
        body: JSON.stringify(payload), timeoutMs: 12000 });
      break;
    } catch (error) {
      ensureCurrent();
      if (error.status) throw error;
      if (attempt === 1) throw new Error(payload.action === "write"
        ? "Ответ о сохранении потерян. Проверьте файл перед новой записью; повтор в этом окне использует тот же ключ."
        : "Ответ о начале файловой операции потерян. Повторите запрос.");
    }
  }
  ensureCurrent();
  const operationId = created?.operation?.id;
  if (typeof operationId !== "string" || !/^[0-9a-f-]{36}$/.test(operationId)) {
    throw new Error("Центр мониторинга вернул неверный ответ.");
  }
  const deadline = Date.now() + 125000;
  while (Date.now() < deadline) {
    ensureCurrent();
    let reply;
    try { reply = await request(`${path}/${encodeURIComponent(operationId)}`, { timeoutMs: 12000 }); }
    catch (error) {
      if (error.status === 404) throw new Error(payload.action === "write"
        ? "Результат сохранения больше недоступен. Проверьте файл перед новой записью."
        : "Файловая операция истекла. Повторите запрос.");
      throw error;
    }
    ensureCurrent();
    const operation = reply?.operation;
    if (operation?.state === "succeeded" || operation?.state === "failed") {
      if (["binary_info", "binary_chunk", "upload_begin", "upload_chunk", "upload_commit", "upload_cancel"].includes(payload.action)) {
        // Large chunks should not remain in Hub memory until the two-minute TTL.
        try { await request(`${path}/${encodeURIComponent(operationId)}`, { method: "DELETE", timeoutMs: 12000 }); }
        catch { /* The Hub will still expire the result. */ }
      }
      if (operation.state === "failed") throw new Error(filesError(operation.result?.code));
      return operation.result;
    }
    if (!operation || !["queued", "running"].includes(operation.state)) {
      throw new Error("Центр мониторинга вернул неверный ответ.");
    }
    await new Promise((resolve) => setTimeout(resolve, 900));
  }
  throw new Error(payload.action === "write"
    ? "Agent не подтвердил сохранение. Проверьте файл перед повторной записью."
    : "Agent не ответил за две минуты. Проверьте локальное разрешение файлов и связь с сервером.");
}

function filesDirty() {
  return Boolean(filesClient.etag) && $("filesText").value !== filesClient.originalText;
}
globalThis.filesHasUnsavedChanges = filesDirty;

function filesWarnUnsavedChanges() {
  showError($("filesError"), "Сначала сохраните или отмените текущие правки.");
}
globalThis.filesWarnUnsavedChanges = filesWarnUnsavedChanges;

function renderFilesButtons() {
  const server = state.servers.find((item) => String(item.id) === String(state.selectedId));
  const ready = Boolean(server?.online && server?.remote_commands_enabled && filesClient.roots.length);
  $("filesServerName").textContent = server?.name || "Выберите сервер";
  $("filesStatus").textContent = !server ? "Нет сервера" : !server.online ? "Сервер не в сети" :
    !server.remote_commands_enabled ? "Нет разрешения Hub" : !filesClient.loaded ? "Подключение" :
      !filesClient.roots.length ? "Нет каталогов" : "Доступен";
  $("filesStatus").className = `status-badge ${ready ? "" : "waiting"}`;
  $("filesRoot").disabled = !ready || filesClient.busy;
  $("filesRefresh").disabled = !Boolean(server?.online && server?.remote_commands_enabled) || filesClient.busy;
  $("filesUpload").disabled = !ready || filesClient.busy;
  $("filesTransferCancel").hidden = !filesClient.transfer;
  $("filesUp").disabled = !ready || filesClient.busy || !filesClient.path;
  const bytes = new TextEncoder().encode($("filesText").value).length;
  $("filesSize").textContent = filesClient.etag ? `${bytes} / 8192 байт UTF-8` : "До 8 КБ UTF-8";
  const dirty = filesDirty();
  $("filesSave").disabled = !ready || filesClient.busy || !dirty || bytes > 8192;
  $("filesDiscard").disabled = !dirty || filesClient.busy;
  $("filesText").disabled = !ready || filesClient.busy || !filesClient.etag;
  $("filesEditorState").textContent = filesClient.busy ? "Выполняется" : dirty ? "Изменён" :
    filesClient.etag ? "Синхронизирован" : "Файл не открыт";
}

function renderFilesEntries() {
  const list = $("filesEntries");
  list.replaceChildren();
  $("filesPath").textContent = `/${filesClient.root}/${filesClient.path}`.replace(/\/$/, "/");
  for (const item of filesClient.lastEntries) {
    const row = document.createElement("div");
    row.className = "files-entry-row";
    const button = document.createElement("button");
    button.type = "button";
    const label = document.createElement("strong");
    label.textContent = `${item.kind === "directory" ? "▣" : "▤"} ${item.name}`;
    const meta = document.createElement("span");
    meta.textContent = item.kind === "directory" ? "Папка" : bytes(item.size);
    button.append(label, meta);
    button.addEventListener("click", () => {
      if (filesDirty()) { showError($("filesError"), "Сначала сохраните или отмените текущие правки."); return; }
      const next = [filesClient.path, item.name].filter(Boolean).join("/");
      if (item.kind === "directory") listFiles(next);
      else openFile(next);
    });
    row.append(button);
    if (item.kind === "file") {
      const download = document.createElement("button");
      download.type = "button";
      download.className = "secondary-button files-download";
      download.textContent = "Скачать";
      download.setAttribute("aria-label", `Скачать ${item.name}`);
      download.disabled = item.size > BINARY_DOWNLOAD_LIMIT || filesClient.busy;
      if (item.size > BINARY_DOWNLOAD_LIMIT) download.title = "Максимальный размер скачивания — 32 МБ";
      download.addEventListener("click", () => {
        if (filesDirty()) { filesWarnUnsavedChanges(); return; }
        prepareBinaryDownload([filesClient.path, item.name].filter(Boolean).join("/"));
      });
      row.append(download);
    }
    list.append(row);
  }
  if (!filesClient.lastEntries.length) {
    const note = document.createElement("p");
    note.className = "advanced-empty";
    note.textContent = "В каталоге нет доступных обычных файлов и папок.";
    list.append(note);
  }
  if (filesClient.truncated) {
    const note = document.createElement("p");
    note.className = "advanced-empty";
    note.textContent = "Показана часть каталога (не более 200 элементов).";
    list.append(note);
  }
}

async function listFiles(path = filesClient.path) {
  if (filesClient.busy || !filesClient.root) return;
  filesClient.busy = true;
  renderFilesButtons();
  clearError($("filesError"));
  const generation = filesClient.generation;
  try {
    const result = await fileOperation({ action: "list", root: filesClient.root, path });
    if (generation !== filesClient.generation) return;
    if (!Array.isArray(result?.entries) || typeof result?.truncated !== "boolean") {
      throw new Error("Центр мониторинга вернул неверный список файлов.");
    }
    filesClient.path = path;
    filesClient.lastEntries = result.entries;
    filesClient.truncated = result.truncated;
    renderFilesEntries();
  } catch (error) {
    if (generation === filesClient.generation) showError($("filesError"), error.message || "Не удалось открыть каталог.");
  } finally {
    if (generation === filesClient.generation) { filesClient.busy = false; renderFilesButtons(); renderFilesEntries(); }
  }
}

async function openFile(path) {
  if (filesClient.busy || !filesClient.root) return;
  filesClient.busy = true;
  renderFilesButtons();
  clearError($("filesError"));
  const generation = filesClient.generation;
  try {
    const result = await fileOperation({ action: "read", root: filesClient.root, path });
    if (generation !== filesClient.generation) return;
    if (!Number.isInteger(result?.size) || result.size < 0 || result.size > 8192 ||
        typeof result.etag !== "string" || !/^[0-9a-f]{64}$/.test(result.etag)) {
      throw new Error("Центр мониторинга вернул неверный файл.");
    }
    let raw;
    try { raw = result.content === "" && result.size === 0 ? new Uint8Array() :
      base64UrlDecode(result.content, result.size, 8192); }
    catch { throw new Error("Центр мониторинга вернул неверный файл."); }
    let text;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(raw); }
    catch { throw new Error("Файл не является корректным текстом UTF-8."); }
    if (text.includes("\0")) throw new Error("Двоичный файл нельзя открыть в редакторе.");
    filesClient.filePath = path;
    filesClient.etag = result.etag;
    filesClient.originalText = text;
    $("filesText").value = text;
    $("filesCurrentFile").textContent = `/${filesClient.root}/${path}`;
  } catch (error) {
    if (generation === filesClient.generation) showError($("filesError"), error.message || "Не удалось открыть файл.");
  } finally {
    if (generation === filesClient.generation) { filesClient.busy = false; renderFilesButtons(); }
  }
}

async function loadFileRoots() {
  if (filesClient.busy) return;
  filesClient.busy = true;
  renderFilesButtons();
  clearError($("filesError"));
  const generation = filesClient.generation;
  try {
    const result = await fileOperation({ action: "roots" });
    if (generation !== filesClient.generation) return;
    if (!Array.isArray(result?.roots) || result.roots.some((root) => typeof root !== "string")) {
      throw new Error("Центр мониторинга вернул неверный список каталогов.");
    }
    filesClient.loaded = true;
    filesClient.roots = result.roots;
    filesClient.root = result.roots[0] || "";
    const select = $("filesRoot");
    select.replaceChildren();
    for (const root of result.roots) {
      const option = document.createElement("option");
      option.value = root;
      option.textContent = root;
      select.append(option);
    }
    select.value = filesClient.root;
  } catch (error) {
    if (generation === filesClient.generation) showError($("filesError"), error.message || "Не удалось узнать доступные каталоги.");
  } finally {
    if (generation === filesClient.generation) {
      filesClient.busy = false;
      renderFilesButtons();
      if (filesClient.root) listFiles("");
    }
  }
}

function filesViewActivated() {
  const server = state.servers.find((item) => String(item.id) === String(state.selectedId));
  if (filesClient.serverId !== (server?.id ?? null)) {
    filesReset();
    filesClient.serverId = server?.id ?? null;
  }
  renderFilesButtons();
  if (server?.online && server?.remote_commands_enabled && !filesClient.loaded && !filesClient.busy) {
    loadFileRoots();
  }
}
globalThis.filesViewActivated = filesViewActivated;

function prepareFileSave() {
  if (!filesDirty() || filesClient.busy || !filesClient.etag) return;
  const text = $("filesText").value;
  const raw = new TextEncoder().encode(text);
  if (raw.length > 8192) { showError($("filesError"), "Файл превышает лимит 8 КБ UTF-8."); return; }
  const server = state.servers.find((item) => String(item.id) === String(filesClient.serverId));
  filesClient.pendingSave = { generation: filesClient.generation, serverId: filesClient.serverId,
    root: filesClient.root, path: filesClient.filePath, etag: filesClient.etag, text, raw,
    key: crypto.randomUUID() };
  $("filesSaveTarget").textContent = `${server?.name || filesClient.serverId}: /${filesClient.root}/${filesClient.filePath}`;
  $("filesSaveSize").textContent = `${raw.length} байт UTF-8. Предыдущая версия будет заменена.`;
  clearError($("filesSaveError"));
  $("filesSaveDialog").showModal();
}

async function confirmFileSave() {
  const save = filesClient.pendingSave;
  if (!save || filesClient.busy || save.generation !== filesClient.generation ||
      save.serverId !== filesClient.serverId || save.root !== filesClient.root ||
      save.path !== filesClient.filePath || save.etag !== filesClient.etag ||
      save.text !== $("filesText").value) {
    showError($("filesSaveError"), "Файл или сервер изменился. Подтвердите сохранение заново.");
    return;
  }
  filesClient.busy = true;
  $("filesSaveConfirm").disabled = true;
  renderFilesButtons();
  const generation = filesClient.generation;
  try {
    const result = await fileOperation({ action: "write", root: save.root, path: save.path,
      etag: save.etag, content: base64UrlEncode(save.raw) }, save.key);
    if (generation !== filesClient.generation) return;
    if (!result || typeof result.etag !== "string" || !/^[0-9a-f]{64}$/.test(result.etag) ||
        result.size !== save.raw.length) throw new Error("Центр мониторинга вернул неверное подтверждение записи.");
    filesClient.etag = result.etag;
    filesClient.originalText = save.text;
    filesClient.pendingSave = null;
    $("filesSaveDialog").close();
    clearError($("filesError"));
  } catch (error) {
    if (generation === filesClient.generation) {
      showError($("filesSaveError"), error.message || "Не удалось сохранить файл.");
      showError($("filesError"), error.message || "Не удалось сохранить файл.");
    }
  } finally {
    if (generation === filesClient.generation) {
      filesClient.busy = false;
      $("filesSaveConfirm").disabled = false;
      renderFilesButtons();
    }
  }
}

function validTransferName(name) {
  const bytes = new TextEncoder().encode(name || "").length;
  return typeof name === "string" && name !== "." && name !== ".." &&
    !/[\\/\x00-\x1f\x7f]/.test(name) && bytes > 0 && bytes <= 255;
}

function binaryInfo(value) {
  if (!value || !Number.isInteger(value.size) || value.size < 0 || value.size > BINARY_DOWNLOAD_LIMIT ||
      typeof value.etag !== "string" || !/^[0-9a-f]{64}$/.test(value.etag) ||
      typeof value.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(value.sha256)) {
    throw new Error("Центр мониторинга вернул неверные сведения о файле.");
  }
  return value;
}

function transferTarget(path) {
  const server = state.servers.find((item) => String(item.id) === String(filesClient.serverId));
  return `${server?.name || filesClient.serverId}: /${filesClient.root}/${path}`;
}

async function prepareBinaryDownload(path) {
  if (filesClient.busy || !filesClient.root || filesDirty()) return;
  filesClient.busy = true;
  renderFilesButtons();
  clearError($("filesError"));
  const generation = filesClient.generation;
  try {
    const info = binaryInfo(await fileOperation({ action: "binary_info", root: filesClient.root, path }));
    if (generation !== filesClient.generation) return;
    filesClient.pendingTransfer = { kind: "download", generation, serverId: filesClient.serverId,
      root: filesClient.root, path, info };
    $("filesTransferHeading").textContent = "Скачать файл на устройство?";
    $("filesTransferTarget").textContent = transferTarget(path);
    $("filesTransferDescription").textContent = `${bytes(info.size)}. Контрольная сумма будет проверена перед сохранением.`;
    $("filesTransferConfirm").textContent = "Скачать";
    clearError($("filesTransferError"));
    $("filesTransferDialog").showModal();
  } catch (error) {
    if (generation === filesClient.generation) showError($("filesError"), error.message || "Не удалось подготовить скачивание.");
  } finally {
    if (generation === filesClient.generation) { filesClient.busy = false; renderFilesButtons(); renderFilesEntries(); }
  }
}

async function prepareBinaryUpload(file) {
  if (filesClient.busy || !filesClient.root || filesDirty() || !file) return;
  if (!validTransferName(file.name) || new TextEncoder().encode([filesClient.path, file.name].filter(Boolean).join("/")).length > 512) {
    showError($("filesError"), "Имя файла не подходит для разрешённого каталога."); return;
  }
  if (!Number.isInteger(file.size) || file.size > BINARY_FILE_LIMIT) {
    showError($("filesError"), "Можно загрузить файл размером до 4 МБ."); return;
  }
  const path = [filesClient.path, file.name].filter(Boolean).join("/");
  const existing = filesClient.lastEntries.find((item) => item.name === file.name);
  if (existing?.kind === "directory") {
    showError($("filesError"), "На сервере уже есть каталог с таким именем."); return;
  }
  filesClient.busy = true;
  renderFilesButtons();
  clearError($("filesError"));
  const generation = filesClient.generation;
  try {
    const info = existing ? binaryInfo(await fileOperation({ action: "binary_info", root: filesClient.root, path })) : null;
    if (info && info.size > BINARY_FILE_LIMIT) {
      throw new Error("Нельзя заменить существующий файл больше 4 МБ. Скачайте его и измените на сервере другим способом.");
    }
    if (generation !== filesClient.generation) return;
    filesClient.pendingTransfer = { kind: "upload", generation, serverId: filesClient.serverId,
      root: filesClient.root, path, file, info };
    $("filesTransferHeading").textContent = info ? "Заменить файл на сервере?" : "Загрузить файл на сервер?";
    $("filesTransferTarget").textContent = transferTarget(path);
    $("filesTransferDescription").textContent = info
      ? `${bytes(file.size)} заменят текущий файл (${bytes(info.size)}). Если он изменился, запись будет отменена.`
      : `${bytes(file.size)} будут записаны как новый файл.`;
    $("filesTransferConfirm").textContent = info ? "Заменить" : "Загрузить";
    clearError($("filesTransferError"));
    $("filesTransferDialog").showModal();
  } catch (error) {
    if (generation === filesClient.generation) showError($("filesError"), error.message || "Не удалось подготовить загрузку.");
  } finally {
    if (generation === filesClient.generation) { filesClient.busy = false; renderFilesButtons(); }
  }
}

async function sha256Hex(raw) {
  const digest = await crypto.subtle.digest("SHA-256", raw);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function checkTransfer(transfer) {
  if (transfer.cancelled) throw new Error("Передача остановлена.");
  if (!filesCurrent(transfer.generation, transfer.serverId, transfer.token, transfer.base)) {
    throw new Error("Сервер или сеанс изменился.");
  }
}

async function downloadBinary(transfer) {
  const { root, path, info } = transfer;
  // A fixed 32 MiB ceiling keeps the Safari/Android Blob fallback bounded.
  const data = new Uint8Array(info.size);
  for (let offset = 0; offset < info.size; offset += BINARY_CHUNK_SIZE) {
    checkTransfer(transfer);
    const item = await fileOperation({ action: "binary_chunk", root, path, etag: info.etag, offset });
    const expected = Math.min(BINARY_CHUNK_SIZE, info.size - offset);
    if (item?.offset !== offset || item?.size !== expected || item?.etag !== info.etag) {
      throw new Error("Центр мониторинга вернул неверную часть файла.");
    }
    let chunk;
    try { chunk = base64UrlDecode(item.content, expected, BINARY_CHUNK_SIZE); }
    catch { throw new Error("Центр мониторинга вернул неверную часть файла."); }
    data.set(chunk, offset);
    $("filesTransferStatus").textContent = `Скачано ${bytes(offset + expected)} из ${bytes(info.size)}.`;
  }
  checkTransfer(transfer);
  if (await sha256Hex(data) !== info.sha256) throw new Error("Контрольная сумма файла не совпала. Скачивание отменено.");
  checkTransfer(transfer);
  const name = path.split("/").slice(-1)[0];
  while (filesClient.downloadUrls.size >= MAX_OUTSTANDING_DOWNLOAD_URLS) {
    const oldest = filesClient.downloadUrls.values().next().value;
    filesClient.downloadUrls.delete(oldest);
    URL.revokeObjectURL(oldest);
  }
  const url = URL.createObjectURL(new Blob([data], { type: "application/octet-stream" }));
  filesClient.downloadUrls.add(url);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.hidden = true;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => {
    if (filesClient.downloadUrls.delete(url)) URL.revokeObjectURL(url);
  }, 60000);
  $("filesTransferStatus").textContent = `Файл «${name}» проверен и передан браузеру для сохранения.`;
}

async function uploadBinary(transfer) {
  const { root, path, file } = transfer;
  let uploadId = null;
  try {
    const data = new Uint8Array(await file.arrayBuffer());
    checkTransfer(transfer);
    if (data.length !== file.size || data.length > BINARY_FILE_LIMIT) throw new Error("Выбранный файл изменился.");
    const digest = await sha256Hex(data);
    checkTransfer(transfer);
    const started = await fileOperation({ action: "upload_begin", root, path, size: data.length,
      sha256: digest, etag: transfer.info?.etag || null });
    if (started?.size !== data.length || typeof started.upload_id !== "string" ||
        !/^[0-9a-f-]{36}$/.test(started.upload_id)) throw new Error("Agent не подтвердил начало загрузки.");
    uploadId = started.upload_id;
    for (let offset = 0; offset < data.length; offset += BINARY_CHUNK_SIZE) {
      checkTransfer(transfer);
      const chunk = data.subarray(offset, offset + BINARY_CHUNK_SIZE);
      const item = await fileOperation({ action: "upload_chunk", root, path, upload_id: uploadId,
        offset, content: base64UrlEncode(chunk) });
      if (item?.received !== offset + chunk.length || item?.size !== data.length) {
        throw new Error("Agent вернул неверное подтверждение части файла.");
      }
      $("filesTransferStatus").textContent = `Загружено ${bytes(item.received)} из ${bytes(data.length)}.`;
    }
    checkTransfer(transfer);
    const saved = await fileOperation({ action: "upload_commit", root, path, upload_id: uploadId });
    if (saved?.size !== data.length || saved?.sha256 !== digest ||
        typeof saved.etag !== "string" || !/^[0-9a-f]{64}$/.test(saved.etag)) {
      throw new Error("Agent не подтвердил сохранение файла.");
    }
    uploadId = null;
    if (filesClient.filePath === path) {
      filesClient.filePath = ""; filesClient.etag = ""; filesClient.originalText = "";
      $("filesText").value = "";
      $("filesCurrentFile").textContent = "Файл обновлён. Откройте его заново, если нужен редактор.";
    }
    $("filesTransferStatus").textContent = `Файл «${file.name}» сохранён на сервере (${bytes(data.length)}).`;
  } finally {
    if (uploadId && filesCurrent(transfer.generation, transfer.serverId, transfer.token, transfer.base)) {
      try { await fileOperation({ action: "upload_cancel", root, path, upload_id: uploadId }); }
      catch { /* A timed-out Agent upload expires from memory. */ }
    }
  }
}

async function confirmBinaryTransfer() {
  const pending = filesClient.pendingTransfer;
  if (!pending || filesClient.busy || pending.generation !== filesClient.generation ||
      pending.serverId !== filesClient.serverId || pending.root !== filesClient.root) return;
  filesClient.pendingTransfer = null;
  $("filesTransferDialog").close();
  const transfer = { ...pending, token: state.token, base: state.base, cancelled: false };
  filesClient.transfer = transfer;
  filesClient.busy = true;
  renderFilesButtons();
  $("filesTransferStatus").textContent = pending.kind === "download" ? "Скачиваем файл…" : "Готовим загрузку…";
  clearError($("filesError"));
  let succeeded = false;
  try {
    if (pending.kind === "download") await downloadBinary(transfer);
    else await uploadBinary(transfer);
    succeeded = true;
  } catch (error) {
    if (pending.generation === filesClient.generation) showError($("filesError"), error.message || "Передача файла не удалась.");
  } finally {
    if (pending.generation === filesClient.generation) {
      filesClient.transfer = null;
      filesClient.busy = false;
      renderFilesButtons();
      renderFilesEntries();
      if (succeeded && pending.kind === "upload") listFiles();
    }
  }
}

$("filesRefresh").addEventListener("click", () => {
  if (filesDirty()) { showError($("filesError"), "Сначала сохраните или отмените текущие правки."); return; }
  if (filesClient.root) listFiles(); else loadFileRoots();
});
$("filesRoot").addEventListener("change", (event) => {
  if (filesDirty()) {
    event.target.value = filesClient.root;
    showError($("filesError"), "Сначала сохраните или отмените текущие правки.");
    return;
  }
  filesClient.root = event.target.value;
  filesClient.path = "";
  filesClient.filePath = "";
  filesClient.etag = "";
  filesClient.originalText = "";
  $("filesText").value = "";
  $("filesCurrentFile").textContent = "Откройте текстовый файл из списка.";
  listFiles("");
});
$("filesUp").addEventListener("click", () => {
  if (filesDirty()) { showError($("filesError"), "Сначала сохраните или отмените текущие правки."); return; }
  listFiles(filesClient.path.split("/").slice(0, -1).join("/"));
});
$("filesText").addEventListener("input", renderFilesButtons);
$("filesDiscard").addEventListener("click", () => { $("filesText").value = filesClient.originalText; renderFilesButtons(); });
$("filesSave").addEventListener("click", prepareFileSave);
$("filesSaveConfirm").addEventListener("click", confirmFileSave);
$("filesSaveCancel").addEventListener("click", () => { if (!filesClient.busy) $("filesSaveDialog").close(); });
$("filesSaveDialog").addEventListener("cancel", (event) => { if (filesClient.busy) event.preventDefault(); });
$("filesSaveDialog").addEventListener("close", () => { if (!filesClient.busy) filesClient.pendingSave = null; });
$("filesUpload").addEventListener("click", () => {
  if (filesDirty()) { filesWarnUnsavedChanges(); return; }
  if (!filesClient.busy) $("filesUploadInput").click();
});
$("filesUploadInput").addEventListener("change", (event) => {
  const file = event.target.files?.[0];
  event.target.value = "";
  if (file) prepareBinaryUpload(file);
});
$("filesTransferConfirm").addEventListener("click", confirmBinaryTransfer);
$("filesTransferBack").addEventListener("click", () => $("filesTransferDialog").close());
$("filesTransferDialog").addEventListener("close", () => {
  if (!filesClient.busy) filesClient.pendingTransfer = null;
});
$("filesTransferCancel").addEventListener("click", () => {
  if (filesClient.transfer) {
    filesClient.transfer.cancelled = true;
    $("filesTransferStatus").textContent = "Останавливаем передачу после текущей части…";
  }
});

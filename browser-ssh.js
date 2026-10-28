/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const pinName = `sovagrid.ssh-host-key:${location.origin}`;
  const fingerprintPattern = /^SHA256:[A-Za-z0-9+/]{43}$/;
  let reviewed = null;
  let busy = false;
  let changedPin = false;

  function secureOrigin() {
    return location.protocol === "https:" ||
      (location.protocol === "http:" && ["127.0.0.1", "localhost"].includes(location.hostname));
  }
  const insecureMessage = "Для SSH-входа откройте эту панель по HTTPS или через локальный SSH-туннель. На обычном HTTP пароль и ключ передавать нельзя.";

  function pin() {
    try { return localStorage.getItem(pinName); } catch { return null; }
  }
  function savePin(value) {
    try { localStorage.setItem(pinName, value); } catch { /* Private browsing may disable storage. */ }
  }
  function error(message) {
    $("sshLoginError").textContent = message;
    $("sshLoginError").hidden = false;
  }
  function clearError() {
    $("sshLoginError").textContent = "";
    $("sshLoginError").hidden = true;
  }
  function updateButton() {
    $("sshConnectButton").disabled = !secureOrigin() || busy || !reviewed || changedPin || !$("sshTrustHost").checked;
    $("sshInspectHost").disabled = !secureOrigin() || busy;
  }
  function showMode(mode) {
    const ssh = mode === "ssh";
    $("browserSshView").hidden = !ssh;
    $("hubLoginView").hidden = ssh;
    $("sshLoginMode").setAttribute("aria-selected", String(ssh));
    $("hubLoginMode").setAttribute("aria-selected", String(!ssh));
    (ssh ? $("sshUsername") : $("username")).focus?.();
  }
  function authMethod() { return $("sshAuthKey").checked ? "private_key" : "password"; }
  function showMethod() {
    const key = authMethod() === "private_key";
    $("sshKeyFields").hidden = !key;
    $("sshPasswordFields").hidden = key;
    $("sshPassword").value = "";
    $("sshPassphrase").value = "";
    $("sshPrivateKey").value = "";
  }
  async function api(path, value, timeoutMs) {
    if (!secureOrigin()) throw new Error("INSECURE_ORIGIN");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(path, { method: "POST", credentials: "omit", cache: "no-store",
        redirect: "error", referrerPolicy: "no-referrer",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(value), signal: controller.signal });
      let result;
      try { result = await response.json(); }
      catch {
        const failure = new Error("SSH_UNAVAILABLE");
        failure.status = response.status;
        throw failure;
      }
      if (!response.ok) {
        const failure = new Error(typeof result?.error === "string" ? result.error : "SSH_UNAVAILABLE");
        failure.status = response.status;
        throw failure;
      }
      return result;
    } catch (failure) {
      if (failure.name === "AbortError") throw new Error("SSH_TIMEOUT");
      throw failure;
    } finally { clearTimeout(timer); }
  }
  function explain(failure) {
    if (failure.status === 404 || failure.status === 502) return "SSH-вход через сайт ещё не включён на этом сервере. Войдите в панель или обновите сервер.";
    if (failure.message === "HOST_KEY_CHANGED") return "Ключ SSH-сервера изменился. Сверьте новый отпечаток вне SovaGrid и повторите проверку.";
    if (failure.message === "AUTH_FAILED") return "SSH не принял эти данные. Проверьте имя пользователя, ключ или пароль.";
    if (failure.message === "GRANT_UNAVAILABLE") return "SSH-вход выполнен, но у пользователя нет root или sudo без запроса пароля для входа в панель.";
    if (failure.message === "RATE_LIMIT") return "Слишком много попыток. Подождите минуту.";
    if (failure.message === "BUSY") return "Сервер занят. Повторите попытку позже.";
    if (failure.message === "INVALID_INPUT") return "Проверьте поля SSH и попробуйте снова.";
    if (failure.message === "SSH_TIMEOUT") return "SSH-сервер не ответил вовремя.";
    return "Не удалось связаться с SSH этого сервера. Панельный вход остаётся доступным.";
  }

  async function inspect() {
    if (!secureOrigin()) { error(insecureMessage); updateButton(); return; }
    if (busy) return;
    busy = true;
    reviewed = null;
    changedPin = false;
    $("sshTrustHost").checked = false;
    $("sshHostKeyReview").hidden = true;
    $("sshReplaceHostKey").hidden = true;
    clearError();
    updateButton();
    try {
      const result = await api("/api/v1/browser-ssh/host-key", {}, 12000);
      if (result.protocol !== 1 || !Number.isSafeInteger(result.port) ||
          result.port < 1 || result.port > 65535 ||
          typeof result.key_type !== "string" || !/^[A-Za-z0-9@._-]{4,96}$/.test(result.key_type) ||
          typeof result.fingerprint !== "string" || !fingerprintPattern.test(result.fingerprint)) {
        throw new Error("INVALID_RESPONSE");
      }
      reviewed = result.fingerprint;
      $("sshTargetPort").textContent = `:${result.port}`;
      $("sshHostFingerprint").textContent = reviewed;
      $("sshHostKeyType").textContent = `Алгоритм: ${result.key_type}`;
      $("sshHostKeyReview").hidden = false;
      const saved = pin();
      if (saved && saved !== reviewed) {
        changedPin = true;
        $("sshReplaceHostKey").hidden = false;
        error("Закреплённый ключ SSH не совпадает с текущим. Подключение заблокировано до ручной сверки и замены.");
      } else if (saved === reviewed) {
        $("sshTrustHost").checked = true;
      }
    } catch (failure) { error(explain(failure)); }
    finally { busy = false; updateButton(); }
  }

  async function connect(event) {
    event.preventDefault();
    if (!secureOrigin()) { error(insecureMessage); updateButton(); return; }
    if (busy || !reviewed || changedPin || !$("sshTrustHost").checked) return;
    const fingerprint = reviewed;
    const previousPin = pin();
    const username = $("sshUsername").value.trim();
    const openServer = $("sshOpenServer")?.value?.trim() || "";
    const openCommands = Boolean($("sshOpenCommands")?.checked);
    const method = authMethod();
    if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/.test(username)) {
      error("Введите имя пользователя SSH без пробелов и специальных символов."); return;
    }
    if (!["password", "private_key"].includes(method)) {
      error("Выберите способ SSH-входа."); return;
    }
    if ([...openServer].length > 80 || /[\x00-\x1f\x7f]/.test(openServer)) {
      error("Укажите имя или ID сервера из панели длиной до 80 символов."); return;
    }
    const file = method === "private_key" ? $("sshPrivateKey").files?.[0] : null;
    if (method === "private_key" && (!file || file.size < 1 || file.size > 65536)) {
      error("Выберите файл приватного ключа размером до 64 КиБ."); return;
    }
    busy = true; // Reserve the reviewed key before the asynchronous file read.
    clearError();
    updateButton();
    let password = "", private_key = "", passphrase = "";
    let sshAuthenticated = false;
    try {
      if (method === "private_key") {
        try { private_key = await file.text(); }
        catch { error("Не удалось прочитать выбранный файл ключа."); return; }
        passphrase = $("sshPassphrase").value;
      } else {
        password = $("sshPassword").value;
      }
      if (!secureOrigin() || reviewed !== fingerprint || pin() !== previousPin || changedPin ||
          !$("sshTrustHost").checked || authMethod() !== method) {
        error("Параметры SSH-входа изменились. Сверьте отпечаток и попробуйте ещё раз."); return;
      }
      if (method === "password" && (!password || password.length > 1024)) {
        error("Введите пароль SSH размером до 1024 символов."); return;
      }
      if (passphrase.length > 1024) { error("Парольная фраза слишком длинная."); return; }
      // The File handle and visible secrets are cleared before the network call.
      $("sshPrivateKey").value = "";
      $("sshPassphrase").value = "";
      $("sshPassword").value = "";
      const result = await api("/api/v1/browser-ssh/login",
        { username, method, fingerprint, password, private_key, passphrase }, 75000);
      password = private_key = passphrase = "";
      if (result.protocol !== 1 || typeof result.grant !== "string" ||
          !/^[A-Za-z0-9_-]{43}$/.test(result.grant)) throw new Error("INVALID_RESPONSE");
      sshAuthenticated = true;
      await globalThis.sovagridRedeemBrowserSSHGrant(result.grant,
        { server: openServer, commands: openCommands });
      savePin(fingerprint);
    } catch (failure) {
      error(sshAuthenticated ? "SSH-вход выполнен, но панель не приняла одноразовый пропуск. Попробуйте снова или войдите по учётной записи панели."
        : explain(failure));
    }
    finally {
      password = private_key = passphrase = "";
      $("sshPrivateKey").value = "";
      $("sshPassphrase").value = "";
      $("sshPassword").value = "";
      busy = false;
      updateButton();
    }
  }

  $("sshTargetHost").textContent = location.hostname;
  $("sshTargetPort").textContent = ":22";
  $("sshLoginMode").addEventListener("click", () => showMode("ssh"));
  $("hubLoginMode").addEventListener("click", () => showMode("hub"));
  $("sshAuthPassword").addEventListener("change", showMethod);
  $("sshAuthKey").addEventListener("change", showMethod);
  $("sshInspectHost").addEventListener("click", () => { void inspect(); });
  $("sshTrustHost").addEventListener("change", updateButton);
  $("sshReplaceHostKey").addEventListener("click", () => {
    const confirmed = globalThis.confirm?.("Заменить ранее закреплённый SSH-ключ только после независимой сверки нового отпечатка?");
    if (!confirmed) return;
    changedPin = false;
    $("sshReplaceHostKey").hidden = true;
    $("sshTrustHost").checked = false;
    clearError();
    updateButton();
  });
  $("browserSshForm").addEventListener("submit", (event) => { void connect(event); });
  if (!secureOrigin()) { error(insecureMessage); updateButton(); }
})();

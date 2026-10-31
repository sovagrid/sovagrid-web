/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

/* An SSH identity is generated and held in this page only. No private bytes
 * enter localStorage, IndexedDB, a service worker or a server until the user
 * explicitly chooses an SSH action. */
(() => {
  const encoder = new TextEncoder();
  const type = encoder.encode("ssh-ed25519");
  const pkcs8Prefix = Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20);
  const $ = (id) => document.getElementById(id);
  const instances = new Map();

  function join(...parts) {
    const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
    let offset = 0;
    for (const part of parts) { result.set(part, offset); offset += part.length; }
    return result;
  }
  function word(value) {
    return Uint8Array.of(value >>> 24, value >>> 16 & 255, value >>> 8 & 255, value & 255);
  }
  function field(bytes) { return join(word(bytes.length), bytes); }
  function base64(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
  }

  async function generateKeyMaterial() {
    if (!globalThis.crypto?.subtle || !globalThis.crypto?.getRandomValues ||
        globalThis.isSecureContext === false) throw new Error("UNSUPPORTED_BROWSER");
    let der, seed, publicBlob, privateBody, privateWire, privateBytes;
    try {
      const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
      der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
      const publicBytes = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
      if (der.length !== 48 || publicBytes.length !== 32 ||
          !pkcs8Prefix.every((byte, index) => der[index] === byte)) throw new Error("UNSUPPORTED_KEY_FORMAT");
      seed = der.slice(pkcs8Prefix.length);
      publicBlob = join(field(type), field(publicBytes));
      const check = crypto.getRandomValues(new Uint8Array(4));
      privateBytes = join(seed, publicBytes);
      privateBody = join(check, check, field(type), field(publicBytes), field(privateBytes),
        field(encoder.encode("sovagrid-browser")));
      const pad = (8 - privateBody.length % 8) % 8;
      const padded = join(privateBody, Uint8Array.from({ length: pad }, (_, index) => index + 1));
      privateBody.fill(0);
      privateBody = padded;
      privateWire = join(encoder.encode("openssh-key-v1\0"), field(encoder.encode("none")),
        field(encoder.encode("none")), field(new Uint8Array()), word(1), field(publicBlob), field(privateBody));
      const body = base64(privateWire).match(/.{1,70}/g).join("\n");
      return {
        publicKey: `ssh-ed25519 ${base64(publicBlob)} sovagrid-browser`,
        privateKey: `-----BEGIN OPENSSH PRIVATE KEY-----\n${body}\n-----END OPENSSH PRIVATE KEY-----\n`,
      };
    } catch (error) {
      if (error.message === "UNSUPPORTED_KEY_FORMAT") throw error;
      throw new Error("UNSUPPORTED_BROWSER");
    } finally {
      der?.fill(0); seed?.fill(0); privateBytes?.fill(0);
      privateBody?.fill(0); privateWire?.fill(0);
    }
  }

  function bind(name, ids) {
    const controls = Object.fromEntries(Object.entries(ids).map(([key, id]) => [key, $(id)]));
    if (Object.values(controls).some((value) => !value)) return;
    const state = { privateKey: null, publicKey: null, revision: 0, generation: 0,
      busy: false, requestBusy: false, downloadRequested: false };
    const instance = { state, controls };
    instances.set(name, instance);
    const message = (value) => { controls.message.textContent = value; };
    const setAvailable = () => {
      const available = Boolean(state.privateKey);
      controls.panel.hidden = !available;
      controls.use.disabled = !available || state.requestBusy;
      controls.copy.disabled = !available;
      controls.download.disabled = !available;
      controls.generate.disabled = state.busy || state.requestBusy;
      controls.passphrase.disabled = available && controls.use.checked;
      if (controls.passphrase.disabled) controls.passphrase.value = "";
    };
    instance.refresh = setAvailable;
    instance.message = message;
    controls.generate.addEventListener("click", async () => {
      if (state.busy || state.requestBusy || state.privateKey && !globalThis.confirm?.(
        "Новый ключ заменит текущий в памяти страницы. Сохраните приватный ключ перед заменой, если уже добавили публичный на сервер.")) return;
      const generation = ++state.generation;
      state.busy = true;
      message("Создаём ключ на этом устройстве…");
      setAvailable();
      try {
        const material = await generateKeyMaterial();
        if (generation !== state.generation) return;
        state.privateKey = material.privateKey;
        state.publicKey = material.publicKey;
        state.downloadRequested = false;
        state.revision++;
        controls.output.value = material.publicKey;
        controls.use.checked = true;
        controls.file.value = "";
        controls.password.value = "";
        controls.keyRadio.checked = true;
        controls.passwordRadio.checked = false;
        controls.keyRadio.dispatchEvent(new Event("change", { bubbles: true }));
        message("Созданный ключ без парольной фразы. Скачайте приватный файл перед подключением и добавьте публичный ключ на сервер.");
      } catch {
        if (generation === state.generation)
          message("Этот браузер не поддерживает создание SSH Ed25519. Используйте приложение SovaGrid или импортируйте существующий ключ.");
      } finally {
        if (generation === state.generation) { state.busy = false; setAvailable(); }
      }
    });
    controls.file.addEventListener("change", () => {
      if (controls.file.files?.length) { controls.use.checked = false; state.revision++; setAvailable(); }
    });
    controls.use.addEventListener("change", () => {
      if (controls.use.checked && state.privateKey) controls.file.value = "";
      state.revision++;
      setAvailable();
    });
    controls.copy.addEventListener("click", async () => {
      if (!state.publicKey) return;
      try {
        await navigator.clipboard.writeText(state.publicKey);
        message("Публичный ключ скопирован. Добавьте его в SSH-ключи сервера или authorized_keys.");
      } catch {
        controls.output.focus?.(); controls.output.select?.();
        message("Копирование недоступно. Выделенный публичный ключ можно скопировать вручную.");
      }
    });
    controls.download.addEventListener("click", () => {
      if (!state.privateKey) return;
      const url = URL.createObjectURL(new Blob([state.privateKey], { type: "application/octet-stream" }));
      const link = document.createElement("a");
      link.href = url; link.download = "sovagrid_ssh_ed25519";
      document.body.append(link); link.click(); link.remove();
      state.downloadRequested = true;
      setTimeout(() => URL.revokeObjectURL(url), 5000);
      message("Скачивание запрошено. Убедитесь, что приватный файл сохранён; храните его как пароль.");
    });
    setAvailable();
  }

  function get(name) {
    const instance = instances.get(name);
    if (!instance?.state.privateKey || instance.state.busy || !instance.controls.use.checked) return null;
    return { privateKey: instance.state.privateKey, revision: instance.state.revision,
      downloadRequested: instance.state.downloadRequested };
  }
  function setBusy(name, busy) {
    const instance = instances.get(name);
    if (!instance) return;
    const { state } = instance;
    const next = Boolean(busy);
    if (next && !state.requestBusy && state.busy) {
      state.generation++;
      state.busy = false;
      instance.message("Дождитесь завершения SSH-запроса, затем создайте ключ.");
    }
    state.requestBusy = next;
    instance.refresh();
  }
  function clear(name, expectedRevision) {
    const instance = instances.get(name);
    if (!instance) return false;
    const { state, controls } = instance;
    if (expectedRevision !== undefined && state.revision !== expectedRevision) return false;
    state.privateKey = state.publicKey = null;
    state.downloadRequested = false;
    state.revision++; state.generation++;
    state.busy = false;
    controls.output.value = "";
    controls.use.checked = false;
    controls.panel.hidden = true;
    controls.message.textContent = "";
    instance.refresh();
    return true;
  }

  bind("login", { generate: "sshGenerateKey", panel: "sshGeneratedKeyPanel",
    output: "sshGeneratedPublicKey", copy: "sshCopyPublicKey", download: "sshDownloadPrivateKey",
    use: "sshUseGeneratedKey", message: "sshGeneratedKeyMessage", file: "sshPrivateKey",
    password: "sshPassword", passphrase: "sshPassphrase", keyRadio: "sshAuthKey", passwordRadio: "sshAuthPassword" });
  bind("setup", { generate: "serverSetupGenerateKey", panel: "serverSetupGeneratedKeyPanel",
    output: "serverSetupGeneratedPublicKey", copy: "serverSetupCopyPublicKey",
    download: "serverSetupDownloadPrivateKey", use: "serverSetupUseGeneratedKey",
    message: "serverSetupGeneratedKeyMessage", file: "serverSetupPrivateKey",
    password: "serverSetupPassword", passphrase: "serverSetupPassphrase", keyRadio: "serverSetupAuthKey",
    passwordRadio: "serverSetupAuthPassword" });
  globalThis.sovagridSSHKeygen = Object.freeze({ generateKeyMaterial, get, setBusy, clear });
  globalThis.addEventListener?.("pagehide", () => { clear("login"); clear("setup"); });
})();

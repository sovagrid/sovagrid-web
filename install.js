/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// Installation stays independent of Hub credentials and roles. The browser
// owns its OS dialog; a declined or unavailable prompt is never called success.
(() => {
  const $ = (id) => document.getElementById(id);
  const mode = window.matchMedia?.("(display-mode: standalone)");
  const loopback = /^(localhost|127(?:\.\d{1,3}){3}|\[::1\])$/.test(location.hostname);
  const secure = window.isSecureContext === true &&
    (location.protocol === "https:" || location.protocol === "http:" && loopback);
  // The managed server keeps this alias when an administrator changes the
  // visible panel route. Manual iPhone shortcuts should be created here too.
  const appURL = new URL("/sovagrid/monitoring/", location.origin).href;
  let deferred = null, prompting = false, confirmed = false, message = "", opener = null;
  const standalone = () => mode?.matches === true || navigator.standalone === true;
  const installed = () => confirmed || standalone();

  function guidance() {
    const agent = navigator.userAgent || "";
    const ios = /iPhone|iPad|iPod/i.test(agent) || navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1;
    const safari = /Safari\//.test(agent) && !/Chrome|Chromium|CriOS|FxiOS|Edg|OPR|OPiOS|Android/.test(agent);
    if (ios) return {
      title: "Добавить на iPhone или iPad",
      intro: safari ? "В Safari это делается через меню «Поделиться»." : "Откройте этот адрес в Safari, затем выполните шаги ниже.",
      steps: ["В Safari откройте меню страницы и выберите «Поделиться» или нажмите видимую кнопку «Поделиться».",
        "В списке действий выберите «На экран Домой». Если пункта нет, найдите его в «Редактировать действия».",
        "Оставьте включённым «Открыть как веб-приложение», если такой переключатель показан, и нажмите «Добавить»."],
      link: "https://support.apple.com/ru-ru/guide/iphone/iphea86e5236/ios", source: "Инструкция Apple",
    };
    if (safari && /Mac/.test(navigator.platform || agent)) return {
      title: "Добавить в Dock на Mac", intro: "В современных версиях Safari панель можно открыть как отдельное приложение.",
      steps: ["В Safari откройте «Поделиться» и выберите «Добавить в Dock».",
        "Проверьте название SovaGrid и нажмите «Добавить». Если пункта нет, используйте актуальный Safari, Chrome или Edge."],
      link: "https://support.apple.com/guide/safari/add-to-dock-ibrw9e991864/mac", source: "Инструкция Apple",
    };
    return {
      title: /Android/.test(agent) ? "Добавить на главный экран" : "Установить через браузер",
      intro: "Если браузер разрешит установку прямо здесь, появится кнопка «Установить».",
      steps: ["Откройте меню браузера. Найдите «Установить приложение», «Установить страницу как приложение» или «Добавить на главный экран».",
        "Если такой команды нет, откройте этот адрес в Chrome или Edge на компьютере/Android либо в Safari на устройстве Apple. Обычная закладка тоже позволяет быстро открыть панель."],
      link: "https://web.dev/learn/pwa/installation/", source: "Об установке веб-приложений",
    };
  }

  function render() {
    document.querySelectorAll("[data-install-open]").forEach((button) => {
      button.textContent = installed() ? "Приложение SovaGrid" : "Сделать приложением";
    });
    const dialog = $("installDialog");
    if (!dialog) return;
    const guide = guidance();
    $("installTitle").textContent = standalone() ? "SovaGrid уже открыт как приложение" :
      confirmed ? "SovaGrid добавлен на устройство" : "SovaGrid — как приложение";
    $("installOrigin").textContent = appURL;
    const onStableRoute = location.pathname === new URL(appURL).pathname;
    $("installStableHint").hidden = onStableRoute || installed();
    $("installStableLink").hidden = onStableRoute || installed();
    $("installStableLink").href = appURL;
    $("installSecureHint").hidden = secure;
    $("installGuide").hidden = installed();
    $("installGuideTitle").textContent = guide.title;
    $("installGuideIntro").textContent = guide.intro;
    $("installSteps").replaceChildren(...guide.steps.map((text) => {
      const item = document.createElement("li"); item.textContent = text; return item;
    }));
    $("installHelp").href = guide.link; $("installHelp").textContent = guide.source;
    $("installConnection").textContent = loopback ?
      "Это локальный адрес на этом устройстве. Если вы открыли панель через SSH-туннель, он должен оставаться включённым на том же порту. Веб-приложение само SSH-соединение не создаёт." :
      "Приложение открывает эту же панель по её адресу. Для работы нужен доступ к серверу; функции и права пользователя остаются такими же, как на сайте.";
    const status = standalone() ? "Панель запущена с иконки устройства в отдельном окне." : confirmed ?
      "Откройте SovaGrid через новую иконку. При необходимости войдите в Hub снова." : message;
    $("installStatus").textContent = status; $("installStatus").hidden = !status;
    const button = $("installConfirm");
    button.hidden = installed() || !secure || (!deferred && !prompting);
    button.disabled = prompting;
    button.textContent = prompting ? "Ожидаем браузер…" : "Установить";
  }

  window.addEventListener("beforeinstallprompt", (event) => {
    if (!secure || installed() || typeof event.prompt !== "function") return;
    event.preventDefault(); deferred = event; message = ""; render();
  });
  window.addEventListener("appinstalled", () => {
    confirmed = true; deferred = null; message = ""; render();
  });
  mode?.addEventListener?.("change", render);
  window.addEventListener("pageshow", render);

  document.querySelectorAll("[data-install-open]").forEach((button) => button.addEventListener("click", () => {
    opener = button;
    render(); $("installDialog").showModal();
  }));
  $("installDialog").addEventListener("close", () => {
    // Safari does not focus a button when it is tapped, so native dialog
    // restoration can leave keyboard and screen-reader focus on the page root.
    if (opener?.isConnected && !opener.closest("[hidden]")) opener.focus({ preventScroll: true });
    opener = null;
  });
  $("installClose").addEventListener("click", () => $("installDialog").close());
  $("installDone").addEventListener("click", () => $("installDialog").close());
  $("installConfirm").addEventListener("click", async () => {
    if (!deferred || prompting || installed() || !secure) return;
    const event = deferred; deferred = null; prompting = true; message = ""; render();
    try {
      // Call synchronously inside this click, before any await. Each browser
      // event is used once; acceptance alone does not set confirmed state.
      const result = await event.prompt();
      const choice = event.userChoice ? await event.userChoice : result;
      message = choice?.outcome === "accepted" ?
        "Браузер принял запрос. Дождитесь завершения установки и откройте иконку SovaGrid." :
        "Установка отменена. Вы можете продолжать пользоваться сайтом или добавить его через меню браузера.";
    } catch {
      message = "Браузер не открыл установку. Попробуйте добавить панель через его меню по инструкции ниже.";
    } finally {
      prompting = false; render();
    }
  });
  render();
})();

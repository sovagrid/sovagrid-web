/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

// This small script runs in the head so the chosen palette is applied before
// the panel and its styles render. Only the preference is stored, never auth.
(() => {
  const key = "sovagrid.theme";
  const allowed = new Set(["system", "light", "dark"]);
  const media = globalThis.matchMedia?.("(prefers-color-scheme: dark)");
  let choice = "system";
  try {
    const saved = localStorage.getItem(key);
    if (allowed.has(saved)) choice = saved;
  } catch { /* Private storage may be unavailable. */ }

  function apply() {
    const resolved = choice === "system" ? (!media || media.matches ? "dark" : "light") : choice;
    document.documentElement.dataset.theme = resolved;
    document.documentElement.dataset.themeChoice = choice;
    const themeColor = document.querySelector('meta[name="theme-color"]');
    themeColor?.setAttribute("content", resolved === "light" ? "#f3f7f5" : "#0a1119");
    const colorScheme = document.querySelector('meta[name="color-scheme"]');
    colorScheme?.setAttribute("content", resolved);
    for (const select of document.querySelectorAll("[data-theme-select]")) select.value = choice;
    if (globalThis.dispatchEvent && globalThis.CustomEvent)
      globalThis.dispatchEvent(new CustomEvent("sovagridthemechange", { detail: { choice, resolved } }));
  }

  function setChoice(next) {
    if (!allowed.has(next)) return;
    choice = next;
    try { localStorage.setItem(key, choice); } catch { /* Current page still follows the choice. */ }
    apply();
  }

  document.addEventListener("DOMContentLoaded", () => {
    apply();
    document.addEventListener("change", (event) => {
      if (event.target?.matches?.("[data-theme-select]")) setChoice(event.target.value);
    });
  });
  if (media?.addEventListener) media.addEventListener("change", () => { if (choice === "system") apply(); });
  else media?.addListener?.(() => { if (choice === "system") apply(); });
  globalThis.SovaGridTheme = Object.freeze({ get choice() { return choice; },
    get resolved() { return document.documentElement.dataset.theme; }, setChoice });
  apply();
})();

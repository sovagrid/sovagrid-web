/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
"use strict";

const BASE = new URL(".", self.location.href).pathname;
const CACHE_PREFIX = `sovagrid-shell:${encodeURIComponent(BASE)}:`;
const CACHE = `${CACHE_PREFIX}v88`;
const SHELL = ["/install.js?v=3", "/install.css?v=1", "/icons/icon-192.png", "/icons/icon-512.png", "/icons/maskable-192.png", "/icons/maskable-512.png", "/icons/apple-touch-icon.png", "/checks.js?v=5", "/checks.css?v=3", "/users.js?v=2", "/access.js?v=1", "/users.css?v=2", "/backups.js?v=2", "/backups-restore.js?v=1", "/backups.css?v=2", "/host-backups.js?v=3", "/host-backups.css?v=3", "/updates.js?v=1", "/updates.css?v=1", "/external-agent-update.js?v=1", "/external-agent-update.css?v=1", "/public-web.css?v=2", "/legal.html", "/legal.css", "/", "/index.html", "/styles.css?v=46", "/theme.css?v=6", "/theme.js?v=1", "/ssh-keygen.js?v=1", "/app.js?v=55", "/direct-ssh.js?v=2", "/direct-ssh.css?v=1", "/browser-ssh.js?v=4", "/files.js?v=4", "/amnezia.js?v=16", "/vpn-jump.js?v=2", "/vpn-jump.css?v=1", "/process-inventory.js?v=1", "/container-logs.js?v=1", "/container-control.js?v=1", "/container-alerts.js?v=1", "/filesystem-alerts.js?v=1", "/service-control.js?v=2", "/telegram.js?v=4", "/monitoring.js?v=3", "/inode.js?v=1", "/public-web.js?v=2", "/local-web.js?v=1", "/journal.js?v=2", "/maintenance.js?v=2", "/vendor/xterm.css?v=1", "/vendor/xterm.js?v=1", "/vendor/addon-fit.js?v=2", "/manifest.webmanifest", "/icons/sovagrid.svg"].map((path) => BASE + path.slice(1));

function shellAssetValid(request, response) {
  if (response.status !== 200 || response.redirected) return false;
  const pathname = new URL(request.url).pathname;
  const type = (response.headers.get("Content-Type") || "").toLowerCase();
  if (pathname.endsWith(".js")) return /^(text|application)\/(javascript|x-javascript)(;|$)/.test(type);
  if (pathname.endsWith(".css")) return /^text\/css(;|$)/.test(type);
  return true;
}
self.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    const requests = SHELL.map((path) => new Request(new URL(path, self.location.origin),
      { credentials: "omit", cache: "reload" }));
    try {
      const responses = await Promise.all(requests.map((request) => fetch(request)));
      if (responses.some((response, index) => !shellAssetValid(requests[index], response)))
        throw new Error("Incomplete SovaGrid app shell");
      const cache = await caches.open(CACHE);
      for (let index = 0; index < requests.length; index++)
        await cache.put(requests[index], responses[index]);
    } catch (error) {
      await caches.delete(CACHE);
      throw error;
    }
  })());
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(Promise.all([
    caches.keys().then((keys) => Promise.all(keys.filter((key) =>
      (key.startsWith(CACHE_PREFIX) && key !== CACHE) ||
      (BASE === "/" && /^sovagrid-shell-v[0-9]+$/.test(key))
    ).map((key) => caches.delete(key)))),
    self.clients.claim(),
  ]));
});

// Only the explicit public app shell is eligible. API, authentication, profile
// downloads, URL parameters and every non-GET request bypass this worker.
self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== self.location.origin ||
      request.headers.has("Authorization") || !SHELL.includes(url.pathname + url.search)) return;
  let update;
  const response = fetch(request).then((response) => {
    const policy = response.headers.get("Cache-Control") || "";
    if (shellAssetValid(request, response) && !/(?:no-store|private)/i.test(policy)) {
      const copy = response.clone();
      update = caches.open(CACHE).then((cache) => cache.put(request, copy));
    }
    return response;
  }).catch(() => caches.open(CACHE).then((cache) => cache.match(request)));
  event.respondWith(response);
  event.waitUntil(response.then(() => update).catch(() => {}));
});

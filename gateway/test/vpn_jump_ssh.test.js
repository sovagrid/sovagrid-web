/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ../../ATTRIBUTION.md. */
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import net from "node:net";
import test from "node:test";
import ssh2 from "ssh2";
import { enrollAmneziaSetup, inspectTargetHostKey, mutateAmneziaSetup,
  previewAmneziaEnrollment, previewAmneziaSetup } from "../server.js";

const CID = "a".repeat(64);
const rawEnrollment = { target: "awg2", container_id: CID, image_id: "sha256:" + "b".repeat(64),
  config_sha256: "c".repeat(64), table_sha256: "d".repeat(64), configured_clients: 0,
  protocol: "amneziawg", interface: "awg0", listen_port: 51820, server_subnet: "10.44.0.0/24" };
const makeKey = () => generateKeyPairSync("rsa", { modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" } }).privateKey;

// These two ephemeral SSH servers only emulate the fixed broker JSON commands.
// They execute no shell, systemd, Docker, or VPN operation on the test computer.
test("real two-hop SSH authenticates both hosts for the complete existing-broker flow", async () => {
  let enrolled = false, installed = false, armed = false, targetAuth = 0, forwarded = 0, adminChecks = 0;
  const commands = [], peers = new Set(), upstreams = new Set();
  const keep = (client) => {
    peers.add(client);
    client.on("error", () => {});
    client.on("close", () => peers.delete(client));
  };
  const preview = () => ({ schema_version: 1, action: "preview", writes: false, selected_target: "awg2",
    marker: armed ? "valid" : "absent", other_marker: "absent", socket_active: armed,
    service_active: armed, installer_ready: true, installed_current: installed,
    can_arm: enrolled && installed && !armed,
    target: enrolled ? { ready: true, container_id: CID, configured_clients: 0, owned_clients: [] } :
      { ready: false, reason: "AWG2 is not enrolled" } });
  const targetServer = new ssh2.Server({ hostKeys: [makeKey()] }, (client) => {
    keep(client);
    client.on("authentication", (ctx) => {
      if (ctx.method === "password" && ctx.username === "root" && ctx.password === "target-secret") {
        targetAuth++; ctx.accept();
      } else ctx.reject();
    }).on("ready", () => client.on("session", (accept) => {
      accept().on("exec", (acceptExec, reject, info) => {
        commands.push(info.command);
        let result;
        if (info.command.endsWith("install-amnezia-control.py preview --target awg2")) result = preview();
        else if (info.command.endsWith("amnezia_admin enroll-preview awg2")) result = rawEnrollment;
        else if (info.command.includes("amnezia_admin enroll awg2 --confirm-container-id " + CID)) {
          assert.match(info.command, /--confirm-table-sha256 d{64}$/);
          enrolled = true; result = { target: "awg2", enrolled: true, configured_clients: 0 };
        } else if (info.command.endsWith("install-amnezia-control.py install")) {
          installed = true; result = { action: "installed", socket_active: false, marker: "absent", target_changed: false };
        } else if (info.command.endsWith("--confirm-maintenance-window I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_AWG2")) {
          armed = true; result = { action: "armed", socket_active: true, marker: "valid",
            selected_target: "awg2", target_changed: false };
        } else { reject(); return; }
        const channel = acceptExec();
        channel.write(JSON.stringify(result)); channel.exit(0); channel.end();
      });
    }));
  });
  const jumpServer = new ssh2.Server({ hostKeys: [makeKey()] }, (client) => {
    keep(client);
    client.on("authentication", (ctx) => {
      if (ctx.method === "password" && ctx.username === "operator" && ctx.password === "relay-secret") ctx.accept();
      else ctx.reject();
    }).on("ready", () => client.on("tcpip", (accept, reject, info) => {
      if (info.destIP !== "127.0.0.1" || info.destPort !== targetServer.address().port) { reject(); return; }
      forwarded++;
      const upstream = net.connect({ host: "127.0.0.1", port: targetServer.address().port });
      upstreams.add(upstream);
      upstream.once("close", () => upstreams.delete(upstream));
      upstream.once("connect", () => { const channel = accept(); channel.pipe(upstream).pipe(channel); });
      upstream.once("error", () => { reject(); upstream.destroy(); });
    }));
  });
  try {
    await new Promise((resolve) => targetServer.listen(0, "127.0.0.1", resolve));
    await new Promise((resolve) => jumpServer.listen(0, "127.0.0.1", resolve));
    const target = { host: "127.0.0.1", port: targetServer.address().port };
    const relay = { host: "127.0.0.1", port: jumpServer.address().port };
    const relayKey = await inspectTargetHostKey(relay);
    const relayLogin = () => ({ ...relay, username: "operator", method: "password",
      fingerprint: relayKey.fingerprint, password: "relay-secret", private_key: "", passphrase: "" });
    const targetKey = await inspectTargetHostKey({ ...target, jump: relayLogin() });
    assert.equal(targetAuth, 0, "target host-key review must precede target authentication");
    const login = () => ({ ...target, target: "awg2", username: "root", method: "password",
      fingerprint: targetKey.fingerprint, password: "target-secret", private_key: "", passphrase: "",
      host_key_blob: targetKey.host_key_blob,
      jump: { ...relayLogin(), host_key_blob: relayKey.host_key_blob } });
    const options = { recheckAdmin: async () => { adminChecks++; } };
    assert.equal((await previewAmneziaSetup(login())).enrolled, false);
    const reviewed = await previewAmneziaEnrollment(login());
    const accepted = await enrollAmneziaSetup({ ...login(), reviewed, confirm: "ENROLL_EXISTING_CONTAINER" }, options);
    const installed = await mutateAmneziaSetup({ ...login(), reviewed: accepted.setup,
      confirm: "INSTALL_AMNEZIA_BROKER" }, "install", options);
    const armedResult = await mutateAmneziaSetup({ ...login(), reviewed: installed.setup,
      confirm: "I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_AWG2" }, "arm", options);
    assert.equal(armedResult.setup.marker, "valid");
    assert.equal(armedResult.setup.jump_host_key_fingerprint, relayKey.fingerprint);
    assert.equal(targetAuth, 11);
    assert.equal(forwarded, 12);
    assert.equal(commands.length, 11);
    assert.equal(adminChecks, 3);
  } finally {
    for (const upstream of upstreams) upstream.destroy();
    for (const peer of peers) peer.end();
    await Promise.all([jumpServer, targetServer].map((server) =>
      new Promise((resolve) => server.close(resolve))));
  }
});

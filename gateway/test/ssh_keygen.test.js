/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import vm from "node:vm";
import ssh2 from "ssh2";

test("browser Ed25519 export is accepted by ssh2 and OpenSSH with the matching public key", async () => {
  const context = vm.createContext({
    crypto: webcrypto, btoa, TextEncoder, Uint8Array, isSecureContext: true,
    document: { getElementById: () => null },
  });
  vm.runInContext(fs.readFileSync(new URL("../../ssh-keygen.js", import.meta.url), "utf8"), context);
  const { publicKey, privateKey } = await context.sovagridSSHKeygen.generateKeyMaterial();
  assert.match(publicKey, /^ssh-ed25519 [A-Za-z0-9+/=]+ sovagrid-browser$/);
  assert.match(privateKey, /^-----BEGIN OPENSSH PRIVATE KEY-----\n/);
  const parsed = ssh2.utils.parseKey(privateKey);
  assert.equal(parsed?.type, "ssh-ed25519", parsed instanceof Error ? parsed.message : "");
  assert.equal(parsed.getPublicSSH().toString("base64"), publicKey.split(" ")[1]);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "sovagrid-browser-key-"));
  const key = path.join(directory, "id_ed25519");
  try {
    fs.chmodSync(directory, 0o700);
    fs.writeFileSync(key, privateKey, { mode: 0o600 });
    const derived = execFileSync("ssh-keygen", ["-y", "-P", "", "-f", key],
      { encoding: "utf8", timeout: 5000 }).trim().split(" ");
    assert.equal(derived[0], "ssh-ed25519");
    assert.equal(derived[1], publicKey.split(" ")[1]);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');

test('both local Caddy listeners send anti-framing headers', () => {
  const source = fs.readFileSync('deploy/Caddyfile.container', 'utf8');
  const blocks = source.split(/(?=^:8080 \{|^localhost:8443 \{)/m).slice(1);
  assert.equal(blocks.length, 2);
  for (const block of blocks) {
    assert.match(block, /header \{\s*Content-Security-Policy "frame-ancestors 'none'"\s*X-Frame-Options "DENY"\s*\}/);
  }
});

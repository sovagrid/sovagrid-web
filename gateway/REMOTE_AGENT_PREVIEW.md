<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 Jigokuraku01 -->

# Remote Agent preflight contract

`POST /api/v1/browser-ssh/target-install-preview` checks whether a separately
managed Ubuntu server is a plausible target for Agent enrollment. It **never
installs or registers anything**. The route requires the current Hub session to
be an unrestricted administrator, plus same-origin HTTPS or local loopback HTTP.

The JSON body has exactly these fields:

| Field | Meaning |
| --- | --- |
| `host`, `port` | Entered SSH target, DNS name/IP and port. |
| `username`, `method`, `password`, `private_key`, `passphrase` | Ephemeral SSH login; `method` is `password` or `private_key`. Unused secret fields are empty strings. |
| `fingerprint` | Independently confirmed `SHA256:` SSH host-key fingerprint. |
| `name` | Proposed Hub display name, 1–80 printable characters. |
| `hub_host`, `hub_port` | Non-loopback IP address and SSH port of this Hub as seen from the target server. |
| `local_port` | Proposed local Agent port on the target, 1024–65535. |

The response contains `action: "install_preview"`, `writes: false`,
`target_kind`, `hub_route`, `preflight_passed`,
`source_verification_required: true`, `reverify_required: true`, and the
selected target and Hub endpoint. `target_kind` has the same coarse values as
`target-status`. `hub_route` is `reachable`, `unreachable`, or `not_checked`.
`preflight_passed` is true only for an otherwise empty Ubuntu target when a
short TCP connection from that target to the Hub SSH endpoint succeeds. It is
an advisory preflight: it does not prove SSH login to the Hub, download the
release, reserve a port, or authorize the Agent. Every check must run again
before a future apply action.

Both SSH connections reverify the exact target host key before authentication.
The second connection executes a fixed Python TCP probe with the Hub endpoint
passed as JSON on stdin. The gateway does not persist SSH secrets. The password
path supports one recognized non-echoed password prompt. OTP and verification
code prompts, multiple questions, and repeated prompts receive no secret.

## Requirements for an apply endpoint

The existing `sovagrid_connect.agent_enrollment.AgentEnrollment` and
`sovagrid-blueprint/deploy/remote_agent.py` own the reviewed, recoverable
enrollment protocol. Applying it from Web requires a dedicated Python worker
with OpenSSH, the verified pinned server-source archive, and a durable private
enrollment journal. The current gateway image is an unprivileged, read-only
Node container without those components. Browser-supplied SSH credentials must
remain transient; after an interruption, the administrator must enter them
again to resume the journaled operation.

The Hub already accepts the browser bearer token on
`/api/v1/agent-enrollments/{id}` and its cancellation route, with a fresh
unrestricted-admin check. A worker adapter can use that bearer and verify
`/api/v1/session` and `/api/v1/session/access` instead of asking the user for a
second Hub password. The Hub-side `hub-*` RPC still needs a narrowly scoped
host-side privileged bridge to manage its tunnel account and authorized key.
No Web apply endpoint should be advertised until those pieces and a two-server
integration test are in place.

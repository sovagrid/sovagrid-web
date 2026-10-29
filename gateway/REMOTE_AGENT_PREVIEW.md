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

## Reviewed Agent enrollment gateway

The same SSH gateway now accepts these `POST` routes after a fresh unrestricted
Hub administrator check, same-origin enforcement and HTTPS (or local loopback
HTTP) enforcement:

| Route suffix under `/api/v1/browser-ssh/agent/` | JSON body |
| --- | --- |
| `prepare` | The exact 12 fields of `target-install-preview` above. |
| `resume` | `request_id` plus the 8 SSH target fields (`host`, `port`, `username`, `method`, `fingerprint`, `password`, `private_key`, `passphrase`). |
| `apply`, `cleanup` | `request_id`, `expected_revision`. |
| `status` | `request_id`. |
| `list` | `{}`. |
| `interrupt` | `{}` or `request_id`. |

`request_id` is a canonical UUID. The browser supplies its current Hub bearer
session in the `Authorization` header; SSH secrets are only in the JSON body of
`prepare` and `resume`. The gateway checks every field, then sends one bounded
JSON line to the fixed `/run/sovagrid-web-agent/control.sock` Unix socket:
`{"action":"prepare","session_token":"…","payload":{…}}`. The worker replies
with one bounded line, either `{"ok":true,"result":{…}}` or
`{"ok":false,"error":"CODE","request_id":"…"}`. `list` returns an array.
The gateway copies only documented public record fields from a successful
reply and discards any unexpected private fields. The worker must independently
recheck the session and bind the reviewed target host-key fingerprint before
any SSH authentication or write. The browser cannot choose the socket path,
remote command, archive, or worker action outside this list.

The existing Connect `AgentEnrollment` protocol owns prepare, apply, resume,
cleanup and its private durable journal. `prepare` checks both hosts, writes a
private recovery journal and stages a verified temporary archive on the target;
its response says `writes: true, activation_writes: false`. It does not create
or start the Agent. `apply` needs the `request_id` and exact revision returned
by `prepare`. A failed or
interrupted apply reports an uncertainty code plus the durable request ID. The
administrator must enter SSH credentials again to resume. The gateway stores
neither SSH secrets nor the borrowed Hub session. The host-side worker and its
socket are installed separately from this unprivileged container; when absent,
these routes return `INSTALLER_UNAVAILABLE`. The UI should advertise applying
an Agent only when the host worker is installed and its end-to-end integration
has passed.

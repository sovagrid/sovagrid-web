# Web Amnezia setup on the Hub host or another Ubuntu host

The browser SSH gateway can manage the Ubuntu host running this Hub or an
entered Ubuntu host reachable from the gateway container over SSH. Every
request uses `POST`, JSON, a same-origin HTTPS request (or loopback HTTP), a
fresh unrestricted Hub admin session, and SSH credentials pinned to the
selected host key. No SSH credential or Amnezia key is stored by the gateway.
The command is always selected by the gateway; the browser never supplies a
shell command.

The existing `/api/v1/browser-ssh/vpn-setup/preview` reads broker state. The
additional paths are:

| Path suffix | Request after the seven SSH fields | Result |
| --- | --- | --- |
| `enroll-preview` | none | Read-only CAS snapshot of an existing AWG2 or WireGuard container |
| `enroll` | `reviewed` from `enroll-preview`, `confirm: "ENROLL_EXISTING_CONTAINER"` | Pin the existing container for SovaGrid administration |
| `install` | `reviewed` from `preview`, `confirm: "INSTALL_AMNEZIA_BROKER"` | Install the verified control broker files without arming it |
| `arm` | fresh `reviewed` from `preview`, `confirm: "I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_AWG2"` or `..._WIREGUARD` | Arm the selected broker |

The seven SSH fields are exactly `username`, `method`, `fingerprint`, `password`,
`private_key`, `passphrase`, and `target` (`awg2` or `wireguard`).
For an entered host, add exactly `host` (IP address or DNS name) and `port`
(1–65535) to those seven fields on every request. First call
`/api/v1/browser-ssh/target-host-key` with `host` and `port`, independently
verify its fingerprint, then submit it as `fingerprint`. Every SSH connection
rechecks that host key. The entered host's responses and `reviewed` snapshots
also contain `scope: "entered_target"`, normalized `host`, `port`, and
`host_key_fingerprint`. The gateway refuses a `reviewed` object from another
host, port or SSH key before any write. The existing seven-field Hub-host
requests and responses retain their original shape.

`enroll-preview` returns `protocol: 1`, `action: "enroll_preview"`,
`writes: false`, `target`, `container_id`, `image_id`, `config_sha256`,
`table_sha256`, `configured_clients`, `vpn_protocol`, `interface`, `listen_port`,
`server_subnet`, `host_key_fingerprint`, and `reverify_required: true`. The
response contains no peer names, private keys, or profiles. `enroll` accepts
that complete object unchanged. It reads the live snapshot again, compares all
fields, and calls the root CLI with the same four CAS pins as desktop Connect:
container ID, image ID, config SHA-256, and client table SHA-256. The root CLI
checks those pins again under its lock. `install` and `arm` also compare a new
broker preview with the reviewed object before calling their fixed root CLI.
`arm` passes the reviewed container ID and the target-specific maintenance
confirmation to the root CLI. All writes verify their result with another
read-only preview.

`SETUP_CHANGED` (HTTP 409) means the user must take a new preview before any
write. `SETUP_UNCERTAIN` (HTTP 503) means the root command may have completed
without a verifiable response; refresh the preview before deciding what to do.
Commands cannot be retried blindly. A short interval remains between the
gateway's last read-only check and the root CLI; the CLI rechecks its own
preconditions, with four atomic CAS pins for enrollment. `install` and `arm`
do not provide an atomic multi-command transaction.

The root `enroll-preview` command may initialize its private lock directory on
first use. Its `writes: false` flag means it does not change the VPN container,
client table, broker, or enrollment record.

The entered host needs root SSH access to prepare compatible `sovagrid-vpn`
source through `POST /api/v1/browser-ssh/vpn-source/preview`, `/apply`, and
`/recover`. These routes require the same exact eight SSH fields as target
status, unrestricted Hub admin access, and the independently reviewed host
fingerprint. Preview stages a verified bundle temporarily, returns four SHA-256
fields in `expected`, the `install|update|current` decision, and
`cleanup_required`; apply requires that entire `expected` object unchanged.
The helper checks the target files again before installing both fixed source
trees. A recovery request cleans up only its owned temporary state. A lost
apply response or `cleanup_required:true` requires a fresh preview before
further action. Source updates refuse an installed Amnezia or WireGuard control
unit or enable marker, even if the unit is currently stopped.
These routes do not create a VPN container, arm a broker, or create a jump
tunnel. The Amnezia routes still require an existing compatible container and
root or passwordless sudo access to their fixed installer.
An SSH reverse tunnel bound only to the Hub host's loopback is not reachable
from the gateway container by this route; a separately configured reachable
SSH endpoint is needed.

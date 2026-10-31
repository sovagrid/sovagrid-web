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
These source routes do not create a VPN container, arm a broker, or create a
jump tunnel. The existing Amnezia broker enrollment routes still require a
running compatible container and root or passwordless sudo access to their
fixed installer.
An SSH reverse tunnel bound only to the Hub host's loopback is not reachable
from the gateway container by this route; a separately configured reachable
SSH endpoint is needed.

## Plain WireGuard broker on an entered Agent

After preparing the verified `sovagrid-vpn` source, the same pinned SSH form
can inspect and install the plain WireGuard control broker through
`POST /api/v1/browser-ssh/wg-control/preview`, `/apply`, and `/recover`. These
routes require a fresh unrestricted Hub admin session, same-origin HTTPS or
loopback, and exactly the eight entered-target SSH fields listed above without
the Amnezia `target` field. Apply adds exactly
`expected: {state_revision, source_revision}` (two lowercase 64-character
SHA-256 values) and `confirm: true`; recover adds `confirm: true`.

The preview is read-only. A full result reports the broker socket and service,
inventory timer and snapshot, dependencies, AppArmor profile, the two revisions,
`can_apply`, and any fixed blocking reason. A degraded preview has no revisions
and cannot authorize apply. The Web Agent and root installer compare the
reviewed revisions again before writing. If recovery is required, only the
separately confirmed recover action is available. The browser clears SSH
secrets before each request and keeps only a tab-scoped uncertainty marker if
the response may have been lost. A fresh preview is required before another
write. Socket deadlines are 120 seconds for preview, 720 seconds for apply,
and 450 seconds for recover; the browser waits slightly longer.

The gateway validates and returns only fixed status fields and fixed error
codes. The install may add Ubuntu packages and enables the root broker socket,
service, and inventory timer. It does not create or activate a WireGuard
interface, VPN instance, or client profile. See the
[Web Agent contract](../../sovagrid-blueprint/deploy/WEB_WIREGUARD_CONTROL.md).

## New AmneziaWG 3.1 container on an entered Ubuntu host

After verified `sovagrid-vpn` source preparation, the independent AmneziaWG
provisioner uses `POST /api/v1/browser-ssh/amnezia-provision/{preview,apply,recover}`.
Only an unrestricted Hub admin on the same HTTPS origin or a loopback origin
may use these routes. All three requests carry exactly the eight pinned SSH
fields. Preview adds `listen_port` (integer UDP port 1–65535), `subnet`
(canonical RFC1918 IPv4 `/24`) and `route_mode` (`full` or `split`). Apply adds
`expected_state` (lowercase 64-character SHA-256) and `confirm: true`; recover
adds only `confirm: true`. SSH port and VPN UDP port are separate fields.

The fixed preview has `writes: false` and reports `can_apply`, source image
digest/cache state, the selected network and route, and `state_revision` when
the target can be observed. A degraded preview has no revision and cannot
authorize apply. The bridge and root CLI recheck the revision before mutation.
`full` is the default internet route; `split` permits only the server VPN
subnet. Apply creates and starts the fixed `amnezia-awg2` Docker container,
activates `awg0`, and publishes the chosen UDP port. It does not enroll,
install, or arm the management broker. Existing containers are never replaced.
After apply, the user must separately inspect and enroll the compatible
running container through the existing broker flow.

The gateway accepts only fixed, bounded result fields and error codes,
compares the returned host, SSH port, fingerprint, and echoed VPN configuration
to the request, and clears submitted SSH secrets. The browser retains only a
tab-scoped uncertainty marker after an unconfirmed apply or recover. A fresh
preview and separately confirmed recover action prevent blind repeats. Socket
read deadlines include SSH preflight: 120 seconds for preview, 480 for apply,
180 for recover; the browser waits slightly longer. Docker publishing a port
does not prove external reachability: a cloud/provider firewall may need a
rule, and a client connection must be tested. The full internet route has not
yet been verified on a live Ubuntu host in this Web repo. See the
[Web Agent contract](../../sovagrid-blueprint/deploy/WEB_AMNEZIA_PROVISION.md).

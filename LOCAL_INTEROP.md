# Local Interop Guide

How to run pathvectord and GoBGP side-by-side on a single machine, observe a
live session, and drive routing events manually or via a scripted exchange.

[gobgp source](https://github.com/osrg/gobgp)

- Quick Tip - If you'd like to use a simulated workflow (There's a set of `just` recipes annotated below in this file, under the header "Justfile recipes"):
  - You'll need 4 separate terminals
  - Run `just gobgp-up` in one, `just dev` in another, `just dashboard` in a third, and `just exchange` in the fourth

---

## Prerequisites

```bash
# GoBGP (installs gobgpd + gobgp CLI)
go install github.com/osrg/gobgp/v4/cmd/gobgpd@v4.6.0
go install github.com/osrg/gobgp/v4/cmd/gobgp@v4.6.0

# Confirm both are on PATH
gobgpd --version
gobgp --version
```

---

## Port layout

| Process     | Binds                          | Notes                                    |
|-------------|--------------------------------|------------------------------------------|
| `gobgpd`    | BGP `:1179`, gRPC `:50051`     | Passive — waits for pathvectord to dial  |
| `pathvectord` | BGP `:1180`, gRPC `:50052`   | Active — dials GoBGP at `127.0.0.1:1179` |

No `sudo` required. Ports above 1024 are unprivileged on macOS.

---

## Config files (workspace root)

**`gobgp.toml`** — GoBGP runs AS 65001, waits for any AS 65002 peer:

```toml
[global.config]
as        = 65001
router-id = "1.0.0.1"
port      = 1179

[[neighbors]]
[neighbors.config]
    neighbor-address = "127.0.0.1"
    peer-as          = 65002
[neighbors.transport.config]
    passive-mode = true
```

**`config.toml`** — pathvectord runs AS 65002, dials GoBGP:

```toml
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"
bgp_port  = 1180
grpc_port = 50052

[[peers]]
address        = "127.0.0.1"
port           = 1179
remote_as      = 65001
import_default = "accept"
export_default = "accept"
```

> **Note on `bgp_id`:** this must be a non-loopback address that exists on your
> machine (RFC 4271 §6.2). `10.0.0.2` works if your Mac has that interface.
> Run `ifconfig | grep "inet "` to find a real address and substitute it.

---

## Manual multi-terminal setup

### Terminal 1 — GoBGP

```bash
gobgpd -f gobgp.toml
```

GoBGP logs the session coming up once pathvectord connects.

### Terminal 2 — pathvectord

```bash
cargo run -p pathvectord -- config.toml
```

You should see tracing output confirming the BGP session reaches Established.

### Terminal 3 — pathvector TUI dashboard

```bash
cargo run -p pathvector -- --address http://127.0.0.1:50052 dashboard
```

The ratatui dashboard shows live peer state and Loc-RIB contents. Press `q` to quit.

### Terminal 4 — command line

All `pathvector` commands need `--address http://127.0.0.1:50052` since the
default port (50051) is taken by GoBGP's own gRPC server.

```bash
PV="cargo run -p pathvector -- --address http://127.0.0.1:50052"

# Peer state
$PV peer list
$PV peer get 127.0.0.1

# RIB queries
$PV route list
$PV route best 10.0.0.0/8
$PV route candidates 10.0.0.0/8

# Originate a route from pathvectord → GoBGP
$PV route originate 192.0.2.0/24 --next-hop 10.0.0.2
$PV route list-originated

# Withdraw it
$PV route withdraw 192.0.2.0/24

# Stream live RIB changes (Ctrl-C to stop)
$PV watch routes
$PV watch peers
```

GoBGP-side commands (no address flag needed — gobgp talks to gobgpd on :50051):

```bash
# Inject a route from GoBGP → pathvectord
gobgp global rib add 10.0.0.0/8 nexthop 10.0.0.1 origin igp
gobgp global rib add 172.16.0.0/12 nexthop 10.0.0.1 origin igp

# Withdraw
gobgp global rib del 10.0.0.0/8

# Observe GoBGP's RIB (shows routes originated by pathvectord)
gobgp global rib

# Peer state from GoBGP's perspective
gobgp neighbor
gobgp neighbor 127.0.0.1
```

---

## Simulated exchange script

Save as `scripts/exchange.sh` and run it with both daemons already running.
It drives a realistic sequence: GoBGP injects a table, pathvectord originates
its own prefix, then routes are withdrawn one by one.

```bash
#!/usr/bin/env bash
# scripts/exchange.sh — simulated BGP exchange for manual testing
#
# Requires: gobgpd + pathvectord already running (see LOCAL_INTEROP.md)
set -euo pipefail

PV="cargo run --quiet -p pathvector -- --address http://127.0.0.1:50052"
GOBGP="gobgp"

log() { echo "[$(date +%T)] $*"; }

# ── Phase 1: GoBGP injects a table ───────────────────────────────────────────

log "GoBGP: announcing prefix table..."
$GOBGP global rib add 10.0.0.0/8     nexthop 10.0.0.1 origin igp
$GOBGP global rib add 172.16.0.0/12  nexthop 10.0.0.1 origin igp
$GOBGP global rib add 192.168.0.0/16 nexthop 10.0.0.1 origin egp
sleep 1

log "pathvectord Loc-RIB after GoBGP announcements:"
$PV route list

# ── Phase 2: pathvectord originates its own prefixes ─────────────────────────

log "pathvectord: originating prefixes..."
$PV route originate 203.0.113.0/24  --next-hop 10.0.0.2
$PV route originate 198.51.100.0/24 --next-hop 10.0.0.2 --med 100
sleep 1

log "GoBGP RIB after pathvectord originations (should show 203.0.113.0/24 and 198.51.100.0/24):"
$GOBGP global rib

# ── Phase 3: policy change — flip a peer to reject-import ────────────────────

log "pathvectord: switching GoBGP peer to reject-import..."
$PV policy set-import 127.0.0.1 reject
sleep 1

log "pathvectord Loc-RIB after policy change (GoBGP routes should be gone):"
$PV route list

log "pathvectord: restoring accept-import..."
$PV policy set-import 127.0.0.1 accept
sleep 1

log "pathvectord Loc-RIB after policy restore:"
$PV route list

# ── Phase 4: withdrawals ──────────────────────────────────────────────────────

log "GoBGP: withdrawing prefixes..."
$GOBGP global rib del 10.0.0.0/8
$GOBGP global rib del 172.16.0.0/12
sleep 1

log "pathvectord: withdrawing originated prefixes..."
$PV route withdraw 203.0.113.0/24
$PV route withdraw 198.51.100.0/24
sleep 1

log "Final state — pathvectord Loc-RIB (expect empty):"
$PV route list

log "Final state — GoBGP RIB (expect only 192.168.0.0/16):"
$GOBGP global rib

log "Done."
```

Make it executable:

```bash
mkdir -p scripts
chmod +x scripts/exchange.sh
./scripts/exchange.sh
```

---

## Justfile recipes

Add these to `justfile` for convenience:

```just
# Start GoBGP for local interop testing (non-privileged ports, no sudo)
gobgp-up:
    gobgpd -f gobgp.toml

# Start pathvectord against the local interop config
dev:
    cargo run -p pathvectord -- config.toml

# Open the live TUI dashboard pointed at the local dev daemon
dashboard:
    cargo run -p pathvector -- --address http://127.0.0.1:50052 dashboard

# Shorthand for pathvector CLI pointed at the local dev daemon
# Usage: just pv route list   |   just pv peer list
pv *args:
    cargo run -p pathvector -- --address http://127.0.0.1:50052 {{args}}

# Run the simulated exchange (gobgp-up + dev must already be running)
exchange:
    ./scripts/exchange.sh
```

Then the full workflow becomes:

```
just gobgp-up          # terminal 1  ← start first
just dev               # terminal 2  ← start second
just dashboard         # terminal 3
just pv route list     # terminal 4
just exchange          # terminal 4 (after both daemons are up)
```

> **Start order matters.** Always start `just gobgp-up` before `just dev`.
> pathvectord is the active side: it dials GoBGP immediately on startup.
> If GoBGP is not yet listening, the TCP connect fails and the BGP FSM starts
> a 120-second ConnectRetry timer (RFC 4271 §8) before trying again.  During
> that window the dashboard will show the peer stuck in Idle/Active even though
> GoBGP is now up.  The session will reach Established automatically once the
> timer fires — you just have to wait up to two minutes.

---

## TCP MD5 authentication (RFC 2385)

TCP MD5 authentication adds an HMAC-MD5 signature to every TCP segment. Both sides
of a BGP session must be configured with the same password. A mismatch causes the TCP
handshake to silently fail — no NOTIFICATION is sent because the TCP SYN itself is
rejected by the kernel before BGP can even start.

> **Platform note.** TCP MD5SIG is enforced at the Linux kernel level. On macOS,
> `pathvectord` configures the socket option (it is a no-op on macOS), so the session
> still establishes — just without kernel-level authentication. Use a Linux host or
> Docker containers to test actual enforcement.

### GoBGP config (`gobgp-md5.toml`)

GoBGP requires `auth-password` under `[neighbors.config]` (not `transport.config`):

```toml
[global.config]
as        = 65001
router-id = "1.0.0.1"
port      = 1179

[[neighbors]]
[neighbors.config]
    neighbor-address = "127.0.0.1"
    peer-as          = 65002
    auth-password    = "shared-bgp-secret"
[neighbors.transport.config]
    passive-mode = true
```

### pathvectord config (`config-md5.toml`)

```toml
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"
bgp_port  = 1180
grpc_port = 50052

[[peers]]
address        = "127.0.0.1"
port           = 1179
remote_as      = 65001
import_default = "accept"
export_default = "accept"
md5_password   = "shared-bgp-secret"
```

### Positive case — matching keys → session establishes

```bash
# Terminal 1
gobgpd -f gobgp-md5.toml

# Terminal 2
cargo run -p pathvectord -- config-md5.toml

# Terminal 3 — confirm Established
cargo run -p pathvector -- --address http://127.0.0.1:50052 peer get 127.0.0.1
```

Expected output includes `state: Established`.

### Negative case — mismatched keys → session never establishes (Linux only)

Change the pathvectord config to use a different password:

```toml
md5_password = "wrong-key"
```

On **Linux** (native Docker or bare metal):

```bash
# The TCP SYN from pathvectord is dropped by the kernel because the MD5 signature
# does not match GoBGP's expected signature. The session stays in Active/Connect.
cargo run -p pathvector -- --address http://127.0.0.1:50052 peer get 127.0.0.1
# Expected: state: Active (never reaches Established)
```

On **macOS** (Docker Desktop), the `setsockopt(TCP_MD5SIG)` call returns `ENOPROTOOPT`
because Docker Desktop's embedded Linux kernel is built without `CONFIG_TCP_MD5SIG`.
`pathvectord` treats this as non-fatal and continues; both sides proceed without
kernel-level authentication, so the session still establishes despite the key mismatch.
This is expected behaviour in the development environment.

### Requirements

- `CAP_NET_ADMIN` is required on Linux for `setsockopt(TCP_MD5SIG)`. When running as
  a non-root user, the listener socket call may fail with `EACCES`. In production, run
  pathvectord as root or grant `CAP_NET_ADMIN` via `setcap`.
- IPv6 peer MD5 authentication is not yet implemented. Configuring `md5_password` on
  a peer with an IPv6 address returns `Unsupported` and the session will not start.
- GoBGP requires knowing the peer's IP before the SYN arrives — it must be configured
  as a static neighbor (`neighbor-address`), not discovered dynamically.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Address already in use` on port 1179/1180 | Stale daemon process | `lsof -i :1179 -i :1180` then `kill <pid>` |
| `unknown service pathvector.v1.PeerService` | CLI hitting GoBGP's gRPC port (50051) | Pass `--address http://127.0.0.1:50052` or use `just pv` |
| Session never reaches Established | `bgp_id` is not a real interface address | Run `ifconfig \| grep "inet "` and set a real address in `config.toml` |
| Peer stuck in Idle/Active after starting `just dev` | `just dev` was started before `just gobgp-up`; RFC 4271 ConnectRetry timer is 120 s | Wait up to 2 minutes — the session will come up automatically. Next time start `just gobgp-up` first |
| GoBGP shows no routes from pathvectord | Export policy is rejecting | Check `import_default`/`export_default` in `config.toml` are both `"accept"` |
| Dashboard shows no peers | Wrong gRPC address | Use `--address http://127.0.0.1:50052` |
| MD5 session stuck in Active (Linux) | Key mismatch — kernel drops SYN | Confirm `auth-password` in GoBGP matches `md5_password` in pathvectord |
| MD5 session establishes despite wrong key (macOS) | Docker Desktop kernel lacks `CONFIG_TCP_MD5SIG`; `ENOPROTOOPT` is treated as non-fatal | Expected on macOS — test enforcement on native Linux |

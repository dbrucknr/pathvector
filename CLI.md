# pathvector CLI

`pathvector` is the command-line management tool for the pathvector BGP daemon.
It connects to a running `pathvectord` over its gRPC management API and provides
subcommands for inspecting peers, querying the Loc-RIB, changing routing policy
at runtime, and displaying a live dashboard.

---

## Installation

```bash
# Build from the workspace root
cargo build -p pathvector --release

# The binary is at
./target/release/pathvector

# Or run directly without installing
cargo run -p pathvector -- <SUBCOMMAND>
```

---

## Global options

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--address <URL>` | `PATHVECTOR_ADDRESS` | `http://127.0.0.1:50051` | Daemon gRPC endpoint |

The `--address` flag is accepted before any subcommand:

```bash
pathvector --address http://10.0.0.2:50051 peer list
```

Or set it once in the environment:

```bash
export PATHVECTOR_ADDRESS=http://10.0.0.2:50051
pathvector peer list
pathvector route list
```

The daemon's gRPC port is configured via `grpc_port` in `pathvectord.toml`
(default `50051`). See [DAEMON.md](DAEMON.md) for the full daemon configuration
reference.

---

## Commands

### `peer list`

Print a table of all configured BGP peers and their current session state.

```bash
pathvector peer list
```

Example output:

```
ADDRESS          REMOTE-AS  TYPE  STATE        UPTIME    RCV  ACC  ADV
10.0.0.1             65001  eBGP  Established  00:03:45    5    4    3
10.0.0.2             65003  eBGP  Idle         —           0    0    0
```

Column reference:

| Column | Description |
|---|---|
| `ADDRESS` | Configured peer IP address |
| `REMOTE-AS` | Remote AS number |
| `TYPE` | `eBGP` (different AS) or `iBGP` (same AS); `—` when idle |
| `STATE` | BGP FSM state — `Established` or `Idle` |
| `UPTIME` | `HH:MM:SS` since the session last reached Established; `—` when idle |
| `RCV` | Routes in Adj-RIB-In (all received prefixes, pre-policy) |
| `ACC` | Routes from this peer that are the current best path in Loc-RIB |
| `ADV` | Routes currently being advertised to this peer (Adj-RIB-Out size) |

---

### `peer get <ADDRESS>`

Print a detailed view of a single peer.

```bash
pathvector peer get 10.0.0.1
```

Example output:

```
Address:    10.0.0.1
Local AS:   65002
Remote AS:  65001
Type:       eBGP (External)
State:      Established
Uptime:     00:03:45
Hold time:  90s
Received:   5 prefix(es)
Accepted:   4 prefix(es)
Advertised: 3 prefix(es)
```

Exits with an error if the address is not a configured peer.

---

### `route list [--peer <ADDRESS>]`

Print a table of all best routes in the Loc-RIB. Pass `--peer` to filter to
routes whose best-path winner is a specific peer.

```bash
# All best routes
pathvector route list

# Only routes learned from 10.0.0.1
pathvector route list --peer 10.0.0.1
```

Example output:

```
PREFIX               PEER             NEXT-HOP         AS-PATH               ORIGIN   MED
192.168.1.0/24       10.0.0.1         10.0.0.1         65001                 IGP      —
10.0.0.0/8           10.0.0.2         10.0.0.2         65003 65100           EGP      100
```

`AS_SET` segments are enclosed in braces: `{65001 65002}`.

---

### `route best <PREFIX>`

Show the best route for a CIDR prefix, or report that no route exists.

```bash
pathvector route best 192.168.1.0/24
```

Example output when a route exists:

```
Prefix:     192.168.1.0/24
Peer:       10.0.0.1 (eBGP)
Next-hop:   10.0.0.1
AS-path:    65001
Origin:     IGP
Local-pref: —
MED:        —
Communities: 65001:100
```

When no route is present:

```
No route for 192.168.1.0/24.
```

---

### `route candidates <PREFIX>`

List every route for a prefix that passed import policy across all peers — not
only the best-path winner. Useful for diagnosing best-path selection when
multiple peers advertise the same prefix.

```bash
pathvector route candidates 192.168.1.0/24
```

Output format is the same table as `route list`.

---

### `policy set-import <ADDRESS> <accept|reject>`

Change the import-policy default for a peer at runtime, without tearing down the
BGP session (soft reconfiguration).

```bash
# Accept all routes from this peer by default
pathvector policy set-import 10.0.0.1 accept

# Revert to RFC 8212 reject-by-default
pathvector policy set-import 10.0.0.1 reject
```

When the policy is changed to `accept`, the daemon immediately re-evaluates the
peer's Adj-RIB-In against the new policy and installs newly accepted routes into
the Loc-RIB. Changes propagate as BGP UPDATEs to all other established peers.

When the policy is changed to `reject`, previously accepted routes are withdrawn
from the Loc-RIB and corresponding WITHDRAWs are sent to peers.

No output on success. Exits with an error message if the peer address is unknown
or the daemon is unreachable.

---

### `policy set-export <ADDRESS> <accept|reject>`

Change the export-policy default for a peer at runtime, without tearing down the
BGP session (soft reconfiguration).

```bash
# Start advertising best routes to this peer
pathvector policy set-export 10.0.0.1 accept

# Stop advertising routes to this peer
pathvector policy set-export 10.0.0.1 reject
```

When the policy is changed to `accept`, the daemon immediately re-evaluates the
entire Loc-RIB for this peer and sends UPDATEs for all newly accepted prefixes.

When changed to `reject`, WITHDRAWs are sent for all previously advertised
prefixes.

No output on success.

---

### `dashboard`

Open a live-updating TUI dashboard showing all peers and routes. Press `q` or
`Ctrl-C` to exit and restore the terminal.

```bash
pathvector dashboard
```

```
┌─ Peers ────────────────────────────────────────────────────────────────────┐
│ ADDRESS        REMOTE-AS  TYPE   STATE        UPTIME    RCV  ACC  ADV      │
│ 10.0.0.1           65001  eBGP   Established  00:03:45    5    4    3      │
└────────────────────────────────────────────────────────────────────────────┘
┌─ Routes ───────────────────────────────────────────────────────────────────┐
│ PREFIX               PEER             NEXT-HOP   AS-PATH    ORIGIN  MED   │
│ 192.168.1.0/24       10.0.0.1         10.0.0.1   65001      IGP     —     │
└────────────────────────────────────────────────────────────────────────────┘
 Daemon: http://127.0.0.1:50051 | Refreshed: 00:00:01 ago | q: quit
```

The daemon is polled every 2 seconds. The status bar shows how long ago the last
successful refresh completed; if a poll fails, the error message appears there
instead.

---

## Policy reload workflow

A common production workflow: start with RFC 8212 reject-all defaults for safety,
let the session come up and verify the peer is healthy, then open up policy
without disrupting the session.

```bash
# 1. Session comes up; no routes flowing (RFC 8212 defaults)
pathvector peer get 10.0.0.1
# State: Established, RCV: 10, ACC: 0

# 2. Accept imports from this peer
pathvector policy set-import 10.0.0.1 accept
pathvector route list
# Routes now appear in Loc-RIB

# 3. Start advertising to a downstream peer
pathvector policy set-export 10.0.0.2 accept
# Downstream peer receives UPDATEs immediately
```

This is the `SetImportDefault` / `SetExportDefault` gRPC RPCs under the hood.
See [DAEMON.md — gRPC management API](DAEMON.md#grpc-management-api) for the raw
Protobuf interface.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Error (connection failed, unknown peer, invalid argument, etc.) |

Error messages are printed to stderr. `route best <PREFIX>` exits `0` even when
no route is found — absence of a route is not an error.

---

## Building the CLI for a remote host

The daemon runs on Linux (typically a router or server). The CLI runs wherever
you have Rust tooling — including macOS for managing a remote Linux daemon.

```bash
# Build a Linux aarch64 release binary (e.g. for an ARM server)
cargo build -p pathvector --release --target aarch64-unknown-linux-gnu

# Copy to the server
scp target/aarch64-unknown-linux-gnu/release/pathvector user@router:/usr/local/bin/
```

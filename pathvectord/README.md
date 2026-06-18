# pathvectord

The BGP daemon. It manages one TCP session per configured peer, maintains a three-table
RIB (Adj-RIB-In, Loc-RIB, Adj-RIB-Out), evaluates import/export policy, and exposes
a gRPC management API for inspecting and controlling operational state.

---

## What does a BGP daemon do?

A BGP daemon is the process that runs the Border Gateway Protocol on a router or server.
It speaks BGP to neighbouring routers (called *peers*), exchanges route advertisements,
and decides which routes to install in the local routing table.

`pathvectord` does three things continuously:

1. **Session management** — opens and maintains TCP connections to each configured peer.
   If a connection drops it retries automatically.

2. **RIB management** — when a peer advertises a prefix, it is stored in Adj-RIB-In
   (raw, pre-policy). If import policy accepts it, it enters Loc-RIB (the decision table)
   and best-path selection picks a winner. The winner goes to Adj-RIB-Out for each peer
   that export policy allows it to reach.

3. **gRPC API** — a management interface (not BGP) where you inspect peers, query
   routes, and change policy at runtime.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Rust ≥ 1.88 | Install via [rustup](https://rustup.rs) |
| `protoc` ≥ 3 | Required at build time for gRPC code generation |

```bash
# macOS
brew install protobuf

# Debian / Ubuntu
sudo apt-get install -y protobuf-compiler
```

---

## Building and running

```bash
# Debug build (fast compile)
cargo build -p pathvectord

# Release build (use this for production)
cargo build -p pathvectord --release

# Run with logging
RUST_LOG=info ./target/release/pathvectord config.toml

# Or run without installing
RUST_LOG=info cargo run -p pathvectord -- config.toml
```

Log levels: `error`, `warn`, `info`, `debug`, `trace`. Use `info` in production — it
shows session lifecycle events and UPDATE processing counts. Use `debug` for per-attribute
parsing detail.

On startup you should see:

```
INFO pathvectord: gRPC management API listening addr=0.0.0.0:50051
INFO pathvectord: session established peer=10.0.0.1 remote_as=65001 hold_time=90 peer_type=External rib_prefixes=0
```

---

## Configuration

pathvectord takes a TOML file as its only argument.

### Minimal example

```toml
[daemon]
local_as = 65002
bgp_id   = "10.0.0.2"

[[peers]]
address   = "10.0.0.1"
remote_as = 65001
```

### `[daemon]` fields

| Field | Type | Default | Description |
|---|---|---|---|
| `local_as` | `u32` | **required** | This router's AS number |
| `bgp_id` | `IPv4` | **required** | Router-ID in dotted-decimal. Must not be a loopback address (`127.0.0.0/8`) — real BGP implementations reject loopback BGP IDs (RFC 6286 §2.1) |
| `hold_time` | `u16` | `90` | Proposed hold timer in seconds. Negotiated down to the peer's value if lower |
| `grpc_port` | `u16` | `50051` | TCP port for the gRPC management API, bound on all interfaces |

### `[[peers]]` fields

| Field | Type | Default | Description |
|---|---|---|---|
| `address` | `IPv4` | **required** | Peer's IP address |
| `remote_as` | `u32` | **required** | Expected remote AS number |
| `port` | `u16` | `179` | TCP port to connect to |
| `import_default` | `"accept"` \| `"reject"` | eBGP: `"reject"`, iBGP: `"accept"` | What to do with routes that don't match any import policy term. eBGP defaults to reject per RFC 8212 |
| `export_default` | `"accept"` \| `"reject"` | eBGP: `"reject"`, iBGP: `"accept"` | What to do with routes that don't match any export policy term |
| `md5_password` | `string` | — | TCP MD5SIG authentication password (RFC 2385). Both sides must use the same password. Linux only; see note below |

### Full example

```toml
[daemon]
local_as   = 65002
bgp_id     = "10.0.0.2"
hold_time  = 90
grpc_port  = 50051

# eBGP peer — RFC 8212 reject-by-default; explicitly opt in
[[peers]]
address        = "10.0.0.1"
remote_as      = 65001
port           = 179
import_default = "accept"
export_default = "accept"

# iBGP peer — same AS, accept-by-default
[[peers]]
address   = "10.0.0.3"
remote_as = 65002
```

> **Note on `bgp_id`:** use a real interface address, not `127.0.0.1`. Run
> `ifconfig | grep "inet "` to find one. The BGP identifier must survive RFC 6286
> duplicate-detection checks that real peers perform.

> **Note on port 179:** BGP's standard port is privileged (< 1024). During
> development, configure both sides to use an unprivileged port (e.g. `1179`).
> pathvectord dials outbound and does not need root for the BGP port itself.

---

## gRPC management API

The API starts alongside the BGP event loop. It is unauthenticated — in production
restrict access with a firewall or bind to a loopback/management interface by running
a reverse proxy in front.

### Services

| Service | Methods |
|---|---|
| `pathvector.v1.PeerService` | `ListPeers`, `GetPeer`, `AddPeer`, `RemovePeer` |
| `pathvector.v1.RibService` | `GetBestRoute`, `ListRoutes`, `ListCandidates` |
| `pathvector.v1.PolicyService` | `SetImportDefault`, `SetExportDefault` |
| `pathvector.v1.OriginationService` | `OriginateRoute`, `OriginateRoutes`, `WithdrawOriginatedRoute`, `WithdrawOriginatedRoutes`, `ListOriginatedRoutes` |
| `pathvector.v1.WatchService` | `WatchRoutes`, `WatchPeers` |

Full schema: [`proto/pathvector/v1/management.proto`](../proto/pathvector/v1/management.proto)

The `pathvector` CLI wraps all services with a human-friendly interface. `grpcurl` works
for ad-hoc queries or scripting:

```bash
brew install grpcurl  # macOS
# or: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
```

pathvectord registers gRPC reflection so `grpcurl` works without `--proto` flags:

```bash
grpcurl -plaintext localhost:50051 list
grpcurl -plaintext localhost:50051 describe pathvector.v1.PeerService
```

### Examples

```bash
# List all configured peers
grpcurl -plaintext localhost:50051 pathvector.v1.PeerService/ListPeers

# Get a single peer
grpcurl -plaintext -d '{"address": "10.0.0.1"}' \
  localhost:50051 pathvector.v1.PeerService/GetPeer

# Get the best route for a prefix
grpcurl -plaintext -d '{"prefix": "192.168.100.0/24"}' \
  localhost:50051 pathvector.v1.RibService/GetBestRoute

# List all best routes in Loc-RIB
grpcurl -plaintext localhost:50051 pathvector.v1.RibService/ListRoutes

# List best routes from a specific peer
grpcurl -plaintext -d '{"peer_address": "10.0.0.1"}' \
  localhost:50051 pathvector.v1.RibService/ListRoutes

# All candidates for a prefix (every peer, not just the best)
grpcurl -plaintext -d '{"prefix": "192.168.100.0/24"}' \
  localhost:50051 pathvector.v1.RibService/ListCandidates

# Change import policy at runtime (no session teardown)
grpcurl -plaintext -d '{"peer": "10.0.0.1", "accept": true}' \
  localhost:50051 pathvector.v1.PolicyService/SetImportDefault

# Originate a route from pathvectord
grpcurl -plaintext -d '{"prefix": "203.0.113.0/24", "next_hop": "10.0.0.2"}' \
  localhost:50051 pathvector.v1.OriginationService/OriginateRoute

# Add a peer at runtime (no daemon restart)
grpcurl -plaintext -d '{
  "address": "10.0.0.3",
  "remote_as": 65003,
  "port": 179,
  "import_default": "POLICY_ACTION_ACCEPT",
  "export_default": "POLICY_ACTION_ACCEPT"
}' localhost:50051 pathvector.v1.PeerService/AddPeer

# Remove a peer at runtime — withdraws all its routes from the Loc-RIB
grpcurl -plaintext -d '{"address": "10.0.0.3"}' \
  localhost:50051 pathvector.v1.PeerService/RemovePeer
```

#### Dynamic peer management

`AddPeer` and `RemovePeer` allow full peer lifecycle management without restarting the
daemon. Other sessions are never interrupted.

`AddPeer` fields:

| Field | Required | Description |
|---|---|---|
| `address` | ✓ | IPv4 address of the new peer |
| `remote_as` | ✓ | Remote AS number. AS 0 and AS 23456 (AS_TRANS) are rejected. |
| `port` | — | TCP port; defaults to 179 |
| `import_default` | — | `POLICY_ACTION_ACCEPT` or `POLICY_ACTION_REJECT`; defaults to RFC 8212 (reject for eBGP, accept for iBGP) |
| `export_default` | — | Same semantics as `import_default` |
| `md5_password` | — | RFC 2385 TCP MD5 authentication key; omit for no MD5 |

`AddPeer` is idempotent — calling it for an already-configured peer is a no-op.
`RemovePeer` returns `NOT_FOUND` if the address is not a configured peer.

### PeerState fields

| Field | Description |
|---|---|
| `address` | Configured peer IP |
| `remote_as` | Remote AS number |
| `local_as` | Local AS number |
| `session_state` | `SESSION_STATE_IDLE` or `SESSION_STATE_ESTABLISHED` |
| `peer_type` | `PEER_TYPE_EXTERNAL` (eBGP) or `PEER_TYPE_INTERNAL` (iBGP); `UNSPECIFIED` when idle |
| `hold_time` | Negotiated hold timer in seconds; `0` when idle |
| `uptime_seconds` | Seconds since last Established; `0` when idle |
| `prefixes_received` | Routes in Adj-RIB-In (all received, pre-policy) |
| `prefixes_accepted` | Routes whose best-path winner is this peer |
| `prefixes_advertised` | Routes currently being sent to this peer (Adj-RIB-Out size) |

### Route fields

| Field | Description |
|---|---|
| `prefix` | CIDR notation, e.g. `"10.0.0.0/8"` |
| `peer_address` | IP of the peer that sent this route |
| `peer_type` | iBGP or eBGP |
| `next_hop` | Forwarding next-hop; empty if absent |
| `as_path` | List of AS_PATH segments; each has `type` and `asns` |
| `origin` | `ORIGIN_IGP`, `ORIGIN_EGP`, or `ORIGIN_INCOMPLETE` |
| `local_pref` | LOCAL_PREF; absent on eBGP routes |
| `med` | MULTI_EXIT_DISC; absent if the peer did not send it |
| `communities` | Standard communities (RFC 1997) as `uint32` values |
| `large_communities` | RFC 8092 large communities: `{global_admin, local_data1, local_data2}` |
| `extended_communities` | RFC 4360 extended communities; each 8 bytes |
| `atomic_aggregate` | `true` if ATOMIC_AGGREGATE attribute is present |
| `aggregator` | Aggregating router `{asn, address}`; absent if not set |

---

## Local interop with GoBGP

The fastest way to get a real BGP session running on a developer machine — no hardware,
no cloud, just two processes on localhost.

**Port layout:**

| Process | Binds | Notes |
|---|---|---|
| `gobgpd` | BGP `:1179`, gRPC `:50051` | Passive — waits for pathvectord to dial |
| `pathvectord` | BGP `:1180`, gRPC `:50052` | Active — dials GoBGP at `127.0.0.1:1179` |

No `sudo` required. Ports above 1024 are unprivileged on macOS.

**Install GoBGP** (requires Go):

```bash
go install github.com/osrg/gobgp/v4/cmd/gobgpd@v4.6.0
go install github.com/osrg/gobgp/v4/cmd/gobgp@v4.6.0
```

**`gobgp.toml`** — GoBGP as AS 65001, passive mode:

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

> `passive-mode = true` is required. Without it GoBGP also dials port 1179
> and connects to itself, flooding NOTIFICATIONs before pathvectord even starts.

**`config.toml`** — pathvectord as AS 65002, dials GoBGP:

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

**Run — 4 terminals:**

```bash
# Terminal 1
gobgpd -f gobgp.toml

# Terminal 2
cargo run -p pathvectord -- config.toml

# Terminal 3 — live TUI dashboard
cargo run -p pathvector -- --address http://127.0.0.1:50052 dashboard

# Terminal 4 — CLI commands
PV="cargo run -p pathvector -- --address http://127.0.0.1:50052"
$PV peer list
$PV route list

# Inject a route from GoBGP into pathvectord
gobgp global rib add 10.0.0.0/8 nexthop 10.0.0.1 origin igp
$PV route best 10.0.0.0/8

# Originate a route from pathvectord to GoBGP
$PV route originate 192.0.2.0/24 --next-hop 10.0.0.2
gobgp global rib

# Withdraw it
$PV route withdraw 192.0.2.0/24
```

Justfile shortcuts (add to your `Justfile`):

```just
gobgp-up:
    gobgpd -f gobgp.toml

dev:
    cargo run -p pathvectord -- config.toml

dashboard:
    cargo run -p pathvector -- --address http://127.0.0.1:50052 dashboard

pv *args:
    cargo run -p pathvector -- --address http://127.0.0.1:50052 {{args}}
```

> **Start order matters.** Always start `gobgp-up` before `dev`. pathvectord
> dials GoBGP immediately. If GoBGP is not listening yet, the BGP FSM starts a
> 120-second `ConnectRetry` timer (RFC 4271 §8) before trying again.

---

## Manual peering with BIRD

BIRD is stricter than GoBGP — useful for validating RFC compliance.

```bash
brew install bird    # macOS
sudo apt install bird2  # Debian/Ubuntu
```

**`bird.conf`:**

```
router id 1.0.0.1;
log stderr all;
protocol device {}

protocol static announce {
    ipv4;
    route 192.168.100.0/24 blackhole;
}

protocol bgp pathvector {
    local as 65001;
    neighbor 127.0.0.1 as 65002;
    passive;
    ipv4 {
        import all;
        export where source ~ [ RTS_STATIC ];
    };
}
```

```bash
sudo bird -c bird.conf -f
# Then in another terminal:
sudo birdc show protocols
sudo birdc show route protocol pathvector
```

---

## TCP MD5 authentication (RFC 2385)

TCP MD5 adds an HMAC-MD5 signature to every TCP segment. Both sides must use the same
password. A mismatch silently drops the TCP handshake before BGP can start.

```toml
[[peers]]
address      = "127.0.0.1"
remote_as    = 65001
md5_password = "shared-bgp-secret"
```

GoBGP:

```toml
[[neighbors]]
[neighbors.config]
    neighbor-address = "127.0.0.1"
    peer-as          = 65002
    auth-password    = "shared-bgp-secret"
```

**Platform notes:**
- **Linux (native):** enforced at the kernel level. Requires `CAP_NET_ADMIN`. A key
  mismatch causes the TCP SYN to be silently dropped — the session will never establish.
- **Linux in Docker Desktop (macOS):** Docker Desktop's embedded kernel is built without
  `CONFIG_TCP_MD5SIG`. `setsockopt(TCP_MD5SIG)` returns `ENOPROTOOPT`, which pathvectord
  treats as non-fatal — the session still establishes but without enforcement.
- **macOS native:** no-op; the `#[cfg(target_os = "linux")]` block is not compiled.
  Sessions always establish regardless of `md5_password`.
- **IPv6 peers:** not yet implemented. Configuring `md5_password` on an IPv6 peer
  returns an error and the session will not start.

---

## Known issues and limitations

| Feature | Status |
|---|---|
| IPv6 route origination via CLI | `route originate` only accepts IPv4; IPv6 origination works via gRPC directly |
| RFC 7606 revised error handling | Malformed path attributes reset the session instead of being treated as withdrawals |
| BGP port binding | Binding port 179 requires root or `CAP_NET_BIND_SERVICE`; use port 1179 in development |

---

## Behavior on restart

When pathvectord starts, it removes all kernel routes it installed in a previous run
(`RTPROT_BGP` protocol tag) before the BGP event loop begins. This prevents stale routes
from being forwarded during the reconvergence window. The cleanup is logged at startup:

```
INFO removing stale BGP routes v4=42 v6=0
```

This is equivalent to BIRD's default `krt` protocol behavior. RFC 4724 graceful restart
(holding stale routes across a planned restart) is not yet implemented.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `NOTIFICATION Code 2 Subcode 3` | `bgp_id` is in `127.0.0.0/8` | Use a non-loopback address, e.g. `10.0.0.2` |
| Session drops on first UPDATE | 4-byte ASN capability mismatch | Already enabled by default; do not remove `FourByteAsn` |
| GoBGP floods NOTIFICATIONs on startup | GoBGP without `passive-mode = true` dials itself | Add `passive-mode = true` to the GoBGP neighbor transport config |
| Peer stuck in Idle/Active after start | pathvectord started before the peer was listening | Wait for the 120s `ConnectRetry` timer, or restart pathvectord after the peer is up |
| `unknown service pathvector.v1.PeerService` | CLI is hitting GoBGP's gRPC (port 50051) | Pass `--address http://127.0.0.1:50052` |
| MD5 session stuck in Active (Linux) | Key mismatch — kernel drops SYN | Verify both sides use the same `md5_password` / `auth-password` |
| MD5 session establishes despite wrong key (macOS Docker) | No `CONFIG_TCP_MD5SIG` | Expected — test enforcement on native Linux |

---

## Crate dependencies

```
pathvector-types
├── pathvector-policy
│   └── pathvector-rib
│       └── pathvectord
└── pathvector-session
    └── pathvectord
pathvector-sys
└── pathvectord
pathvector-client
└── pathvector (CLI)
```

`pathvectord` assembles all layers. It is the only binary crate that links against
`pathvector-sys` for Linux FIB and TCP MD5 support.

---

## License

MIT

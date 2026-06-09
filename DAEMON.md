# Running pathvectord

`pathvectord` is the BGP daemon binary. It manages one TCP session per configured peer, maintains a three-table RIB (Adj-RIB-In, Loc-RIB, Adj-RIB-Out), evaluates import and export policies, and exposes a gRPC management API for querying operational state.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Rust ≥ 1.88 | Install via [rustup](https://rustup.rs) |
| `protoc` ≥ 3 | Required at build time for gRPC codegen — see below |

**Install `protoc`:**

```bash
# macOS
brew install protobuf

# Debian / Ubuntu
sudo apt-get install -y protobuf-compiler

# Fedora / RHEL
sudo dnf install -y protobuf-compiler
```

---

## Building

```bash
# Debug build (fast compile, unoptimised)
cargo build -p pathvectord

# Release build (optimised — use this for production)
cargo build -p pathvectord --release
```

The release binary is at `target/release/pathvectord`.

---

## Configuration

pathvectord is configured via a TOML file passed as the first argument. A minimal config connecting to a single eBGP peer:

```toml
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"

[[peers]]
address   = "10.0.0.1"
remote_as = 65001
```

### `[daemon]` fields

| Field | Type | Default | Description |
|---|---|---|---|
| `local_as` | `u32` | **required** | Local AS number |
| `bgp_id` | `IPv4` | **required** | BGP router-ID in dotted-decimal. Must not be a loopback address (`127.0.0.0/8`) when peering with implementations that validate the BGP Identifier field (RFC 6286 §2.1) |
| `hold_time` | `u16` | `90` | Proposed hold-timer in seconds. Negotiated down to the peer's value if lower |
| `grpc_port` | `u16` | `50051` | TCP port the gRPC management API listens on, bound to all interfaces (`0.0.0.0:<port>`) |

### `[[peers]]` fields

| Field | Type | Default | Description |
|---|---|---|---|
| `address` | `IPv4` | **required** | Peer IP address to connect to |
| `remote_as` | `u32` | **required** | Expected remote AS number |
| `port` | `u16` | `179` | TCP port to connect to |
| `import_default` | `"accept"` \| `"reject"` | eBGP: `"reject"`, iBGP: `"accept"` | Default action for routes that do not match any import policy term. eBGP defaults to `"reject"` per RFC 8212 |
| `export_default` | `"accept"` \| `"reject"` | eBGP: `"reject"`, iBGP: `"accept"` | Default action for routes that do not match any export policy term |

### Example: full configuration

```toml
[daemon]
local_as   = 65002
bgp_id     = "10.0.0.2"
hold_time  = 90
grpc_port  = 50051

# eBGP peer — reject-by-default import/export per RFC 8212
[[peers]]
address        = "10.0.0.1"
remote_as      = 65001
port           = 179
import_default = "accept"   # opt-in: accept all routes from this peer
export_default = "accept"   # opt-in: advertise all best routes to this peer

# iBGP peer — accept-by-default import/export
[[peers]]
address   = "10.0.0.3"
remote_as = 65002           # same AS = iBGP
```

---

## Running

```bash
# With structured logging at INFO level
RUST_LOG=info cargo run -p pathvectord -- config.toml

# Or run the release binary directly
RUST_LOG=info ./target/release/pathvectord config.toml
```

**Log levels:** `error`, `warn`, `info`, `debug`, `trace`. `info` is the right level for production — it surfaces session lifecycle events and UPDATE processing counts. Use `debug` to see per-attribute parsing decisions.

On startup pathvectord logs:

```
INFO pathvectord: gRPC management API listening addr=0.0.0.0:50051
INFO pathvectord: session established peer=10.0.0.1 remote_as=65001 hold_time=90 peer_type=External rib_prefixes=0
```

BGP uses port 179. If you are peering on that port, the daemon needs to bind a privileged port via a capability or by running as root. During development, configure both sides to use an unprivileged port (e.g. 1179) instead.

---

## gRPC management API

The management API starts automatically alongside the BGP event loop. It is unauthenticated and binds on all interfaces — in production, restrict access with a firewall or bind to a loopback/management interface.

### Services

| Service | Methods |
|---|---|
| `pathvector.v1.PeerService` | `ListPeers`, `GetPeer` |
| `pathvector.v1.RibService` | `GetBestRoute`, `ListRoutes`, `ListCandidates` |

The full schema is at [`proto/pathvector/v1/management.proto`](proto/pathvector/v1/management.proto).

### Querying with grpcurl

[`grpcurl`](https://github.com/fullstorydev/grpcurl) is the standard CLI for ad-hoc gRPC queries.

```bash
# macOS
brew install grpcurl

# Go
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
```

pathvectord registers gRPC server reflection at startup, so `grpcurl` works without any `--proto` flags. All services and their schemas are discoverable at runtime:

```bash
# List all registered services
grpcurl -plaintext localhost:50051 list

# Describe a service
grpcurl -plaintext localhost:50051 describe pathvector.v1.PeerService
```

All examples below assume the daemon is running locally on the default port.

---

#### List all configured peers

```bash
grpcurl -plaintext localhost:50051 pathvector.v1.PeerService/ListPeers
```

Example response:

```json
{
  "peers": [
    {
      "address": "10.0.0.1",
      "remoteAs": 65001,
      "localAs": 65002,
      "sessionState": "SESSION_STATE_ESTABLISHED",
      "peerType": "PEER_TYPE_EXTERNAL",
      "holdTime": 90,
      "uptimeSeconds": "142",
      "prefixesReceived": 4,
      "prefixesAccepted": 4,
      "prefixesAdvertised": 1
    }
  ]
}
```

#### Get a single peer

```bash
grpcurl -plaintext -d '{"address": "10.0.0.1"}' \
  localhost:50051 pathvector.v1.PeerService/GetPeer
```

Returns `NOT_FOUND` if the address is not a configured peer, `INVALID_ARGUMENT` if the address is not valid IPv4.

---

#### Get the best route for a prefix

```bash
grpcurl -plaintext -d '{"prefix": "192.168.100.0/24"}' \
  localhost:50051 pathvector.v1.RibService/GetBestRoute
```

Example response when a route exists:

```json
{
  "found": true,
  "route": {
    "prefix": "192.168.100.0/24",
    "peerAddress": "10.0.0.1",
    "peerType": "PEER_TYPE_EXTERNAL",
    "nextHop": "10.0.0.1",
    "asPath": [
      { "type": "TYPE_SEQUENCE", "asns": [65001] }
    ],
    "origin": "ORIGIN_IGP"
  }
}
```

When no route exists: `{ "found": false }`.

#### List all best routes in the Loc-RIB

```bash
grpcurl -plaintext localhost:50051 pathvector.v1.RibService/ListRoutes
```

#### List best routes from a specific peer

```bash
grpcurl -plaintext -d '{"peer_address": "10.0.0.1"}' \
  localhost:50051 pathvector.v1.RibService/ListRoutes
```

#### List all candidate routes for a prefix

Returns every route for the prefix that passed import policy, across all peers. The best route among them is the one returned by `GetBestRoute`.

```bash
grpcurl -plaintext -d '{"prefix": "192.168.100.0/24"}' \
  localhost:50051 pathvector.v1.RibService/ListCandidates
```

---

### PeerState fields reference

| Field | Description |
|---|---|
| `address` | Configured peer IP |
| `remote_as` | Remote AS number |
| `local_as` | Local AS number |
| `session_state` | `SESSION_STATE_IDLE` or `SESSION_STATE_ESTABLISHED` |
| `peer_type` | `PEER_TYPE_EXTERNAL` (eBGP) or `PEER_TYPE_INTERNAL` (iBGP); `UNSPECIFIED` when idle |
| `hold_time` | Negotiated hold-timer in seconds; `0` when idle |
| `uptime_seconds` | Seconds since last Established event; `0` when idle |
| `prefixes_received` | Routes in Adj-RIB-In — all received prefixes, pre-policy |
| `prefixes_accepted` | Routes in Loc-RIB whose best-path winner is this peer |
| `prefixes_advertised` | Routes in Adj-RIB-Out — currently being sent to this peer |

### Route fields reference

| Field | Description |
|---|---|
| `prefix` | CIDR notation, e.g. `"10.0.0.0/8"` |
| `peer_address` | IP of the peer that sent this route |
| `peer_type` | iBGP or eBGP |
| `next_hop` | Forwarding next-hop; empty string if absent |
| `as_path` | List of AS_PATH segments; each has `type` and `asns` |
| `origin` | `ORIGIN_IGP`, `ORIGIN_EGP`, or `ORIGIN_INCOMPLETE` |
| `local_pref` | LOCAL_PREF value; absent on eBGP routes |
| `med` | MULTI_EXIT_DISC; absent if the peer did not send it |
| `communities` | Standard communities (RFC 1997) as raw `uint32` values |
| `large_communities` | RFC 8092 large communities: `{global_admin, local_data1, local_data2}` |
| `extended_communities` | RFC 4360 extended communities; each 8 bytes |
| `atomic_aggregate` | `true` if ATOMIC_AGGREGATE attribute is present |
| `aggregator` | Aggregating router `{asn, address}`; absent if not set |

---

## Interoperability

pathvectord has been validated against GoBGP 4.x with full session lifecycle: OPEN
negotiation, KEEPALIVE exchange, UPDATE announce and withdraw, and clean session
teardown. See [TESTING.md — End-to-end tests](TESTING.md#end-to-end-tests) for the
Docker-based automated suite. The sections below cover manual exploration against
GoBGP and BIRD on the same host — useful for stepping through protocol behaviour,
inspecting logs in real time, or validating a specific config change by hand.

**Easiest path — Docker Compose (no native install required):**

```sh
just e2e-images   # build both images once
just e2e-up       # start gobgpd + pathvectord in the background
just e2e-logs     # stream logs from both containers
just e2e-down     # stop and clean up
```

Port 51200 (pathvectord gRPC) is mapped to the host so `grpcurl` and
`pathvector-client` work normally against the compose environment.

---

### Manual peering with GoBGP

GoBGP is a pure-Go BGP implementation with a convenient CLI for route injection.
It only ships Linux binaries, so macOS users must use the Docker path above or
cross-compile from source. On Linux:

```sh
go install github.com/osrg/gobgp/v4/cmd/gobgpd@v4.6.0
go install github.com/osrg/gobgp/v4/cmd/gobgp@v4.6.0
```

**GoBGP configuration** (`gobgp.toml`):

```toml
[global.config]
  as        = 65001
  router-id = "1.0.0.1"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "127.0.0.1"
    peer-as          = 65002
  [neighbors.transport.config]
    passive-mode = true   # accept incoming connections; do not dial out
```

`passive-mode = true` is required. Without it GoBGP also dials `127.0.0.1:179`
and connects to its own listener, producing a flood of NOTIFICATION Code 2
Subcode 3 rejections before pathvectord even starts.

**pathvectord configuration** (`config.toml`):

```toml
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"   # must not be a loopback address
hold_time = 90

[[peers]]
address        = "127.0.0.1"
remote_as      = 65001
import_default = "accept"
export_default = "accept"
```

**Start GoBGP** (requires root for port 179):

```sh
sudo gobgpd -f gobgp.toml --pprof-disable
```

**Start pathvectord** (in a separate terminal):

```sh
RUST_LOG=info cargo run -p pathvectord -- config.toml
```

Expected log on a successful handshake:

```
INFO pathvectord: session established peer=127.0.0.1 remote_as=65001 hold_time=90 peer_type=External rib_prefixes=0
```

**Announce a route from GoBGP:**

```sh
gobgp global rib add 192.168.100.0/24 nexthop 10.0.0.1 origin igp
```

pathvectord logs:

```
INFO pathvectord: processed UPDATE peer=127.0.0.1 withdrawn=0 accepted=1 rib_size=1
```

Query the route through the management API:

```sh
grpcurl -plaintext localhost:51200 pathvector.v1.RibService/GetBestRoute \
  '{"prefix": "192.168.100.0/24"}'
```

**Withdraw the route:**

```sh
gobgp global rib del 192.168.100.0/24
```

pathvectord logs:

```
INFO pathvectord: processed UPDATE peer=127.0.0.1 withdrawn=1 accepted=0 rib_size=0
```

**Inspect the GoBGP session from GoBGP's side:**

```sh
gobgp neighbor 127.0.0.1          # session state and counters
gobgp global rib                   # routes GoBGP has in its own RIB
gobgp neighbor 127.0.0.1 adj-in   # routes received from pathvectord
```

---

### Manual peering with BIRD

BIRD is a widely-deployed BGP implementation (used by many IXP route servers) and
is stricter about RFC compliance than GoBGP — a useful second data point.

**Install:**

```sh
# macOS
brew install bird

# Debian/Ubuntu
sudo apt install bird2
```

BIRD also requires root for port 179.

**BIRD configuration** (`bird.conf`, BIRD 2.x syntax):

```
# bird.conf — peer with pathvectord on the same host
router id 1.0.0.1;

log stderr all;   # log to stderr for interactive sessions

protocol device {}

# Static routes to export to pathvectord.
# Edit this block and run `birdc configure` to add/remove routes at runtime.
protocol static announce {
    ipv4;
    route 192.168.100.0/24 blackhole;
    route 10.10.0.0/16    blackhole;
}

protocol bgp pathvector {
    local as 65001;
    neighbor 127.0.0.1 as 65002;
    passive;   # accept incoming connections; pathvectord dials us

    ipv4 {
        import all;                            # accept routes from pathvectord
        export where source ~ [ RTS_STATIC ];  # send only our static routes
    };
}
```

The `blackhole` next-hop is correct for static routes that exist only to be
advertised via BGP — BIRD will not try to forward packets to them.

**pathvectord configuration** (same as the GoBGP example above).

**Start BIRD** (foreground for easy Ctrl-C):

```sh
# macOS / Linux
sudo bird -c bird.conf -f
```

On Linux with the system package, BIRD may expect its config at
`/etc/bird/bird.conf`. Use `-c /path/to/bird.conf` to override.

**Start pathvectord** (in a separate terminal):

```sh
RUST_LOG=info cargo run -p pathvectord -- config.toml
```

**Inspect the session from BIRD's side:**

```sh
sudo birdc show protocols                      # all protocols and their state
sudo birdc show protocols pathvector           # detail for the BGP session
sudo birdc show route                          # BIRD's full RIB
sudo birdc show route protocol pathvector      # routes learned from pathvectord
sudo birdc show bgp sessions                   # BGP session table
```

A healthy session shows `pathvector  BGP        ---        up` in
`show protocols`.

**Announce a new route at runtime:**

BIRD does not have a `gobgp global rib add`-style CLI. The standard approach
is to add a `route` line to the `static announce` protocol block and reload:

```sh
# 1. Edit bird.conf — add to the static announce protocol:
#      route 203.0.113.0/24 blackhole;

# 2. Reload without resetting BGP sessions:
sudo birdc configure
```

pathvectord will receive the UPDATE and log the install.

**Withdraw a route:**

Remove the `route` line from the `static announce` block and reload:

```sh
sudo birdc configure
```

---

### What to look for in both cases

| Signal | Meaning |
|---|---|
| `session established` in pathvectord logs | OPEN + KEEPALIVE exchange succeeded; 4-byte ASN negotiated |
| `processed UPDATE … accepted=N` | Route passed import policy and is in the Loc-RIB |
| `GetBestRoute` returns the prefix | Management API and RIB are consistent |
| Hold timer maintained (keepalives every 30 s at hold_time=90) | Timer logic and KEEPALIVE encoding are correct |
| `session terminated` after Ctrl-C on peer | NOTIFICATION teardown is clean; RIB cleared |
| No unexpected NOTIFICATION messages | Codec and capability negotiation are RFC-compliant |

### Known gotchas

| Symptom | Cause | Fix |
|---|---|---|
| NOTIFICATION Code 2 Subcode 3 (Bad BGP Identifier) | `bgp_id` is in `127.0.0.0/8` — real BGP implementations reject loopback BGP IDs | Use a non-loopback address, e.g. `10.0.0.2` |
| Session drops on first UPDATE | `FourByteAsn` capability omitted — peer sends 2-byte AS_PATH, decoder reads 4 bytes per ASN | `Capability::FourByteAsn(local_as)` is already added by default; do not remove it |
| Repeated self-connection NOTIFICATIONs (GoBGP) | GoBGP dials its own listener when `passive-mode` is not set | Set `passive-mode = true` in the GoBGP neighbor transport config |
| `Permission denied` binding port 179 | BGP uses a privileged port | Run the peer daemon with `sudo`; pathvectord connects outbound so does not need root |
| BIRD session stays `Active` | BIRD is in passive mode — pathvectord must connect first | Confirm pathvectord is running and pointing to the correct address |

---

## What is not yet implemented

| Feature | Notes |
|---|---|
| `pathvector` CLI | Typed gRPC client CLI — on the roadmap as `pathvector-client` |
| Runtime policy reload via gRPC | `reapply_import_policy` exists but export propagation not yet wired |
| IPv6 RIB | Session layer parses IPv6 MP_REACH/UNREACH; daemon tables are IPv4-only |
| Docker image | Done — `e2e/Dockerfile.pathvectord`; see `just e2e-images`. A standalone production image (separate from the test image) is not yet published. |

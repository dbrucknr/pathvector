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

Because pathvectord does not yet expose gRPC server reflection, pass the proto file and include path explicitly:

```bash
PROTO_FLAGS="-proto proto/pathvector/v1/management.proto -import-path proto"
```

All examples below assume the daemon is running locally on the default port. Run them from the workspace root so the proto path resolves correctly.

---

#### List all configured peers

```bash
grpcurl -plaintext \
  -proto proto/pathvector/v1/management.proto \
  -import-path proto \
  localhost:50051 pathvector.v1.PeerService/ListPeers
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
grpcurl -plaintext \
  -proto proto/pathvector/v1/management.proto \
  -import-path proto \
  -d '{"address": "10.0.0.1"}' \
  localhost:50051 pathvector.v1.PeerService/GetPeer
```

Returns `NOT_FOUND` if the address is not a configured peer, `INVALID_ARGUMENT` if the address is not valid IPv4.

---

#### Get the best route for a prefix

```bash
grpcurl -plaintext \
  -proto proto/pathvector/v1/management.proto \
  -import-path proto \
  -d '{"prefix": "192.168.100.0/24"}' \
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
grpcurl -plaintext \
  -proto proto/pathvector/v1/management.proto \
  -import-path proto \
  localhost:50051 pathvector.v1.RibService/ListRoutes
```

#### List best routes from a specific peer

```bash
grpcurl -plaintext \
  -proto proto/pathvector/v1/management.proto \
  -import-path proto \
  -d '{"peer_address": "10.0.0.1"}' \
  localhost:50051 pathvector.v1.RibService/ListRoutes
```

#### List all candidate routes for a prefix

Returns every route for the prefix that passed import policy, across all peers. The best route among them is the one returned by `GetBestRoute`.

```bash
grpcurl -plaintext \
  -proto proto/pathvector/v1/management.proto \
  -import-path proto \
  -d '{"prefix": "192.168.100.0/24"}' \
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

For a full walkthrough of peering pathvectord against GoBGP and announcing routes, see [TESTING.md — Interoperability testing](TESTING.md#interoperability-testing).

The short version: pathvectord has been validated against GoBGP 4.x with full session lifecycle (OPEN negotiation, KEEPALIVE exchange, UPDATE announce and withdraw). The key config requirements are:

- `bgp_id` must not be a loopback address
- Include `Capability::FourByteAsn` (already the default — do not remove it)
- Use `passive-mode = true` in GoBGP to avoid self-connection loops

---

## What is not yet implemented

| Feature | Notes |
|---|---|
| gRPC server reflection | Required for `grpcurl` without `--proto` flags; not yet added |
| `pathvector` CLI | Typed gRPC client CLI — on the roadmap as `pathvector-client` |
| Runtime policy reload via gRPC | `reapply_import_policy` exists but export propagation not yet wired |
| IPv6 RIB | Session layer parses IPv6 MP_REACH/UNREACH; daemon tables are IPv4-only |
| Docker image | Planned: `FROM debian:slim`, single binary, config mount, gRPC port exposed |

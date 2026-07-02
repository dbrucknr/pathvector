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
| `metrics_port` | `u16` | — | TCP port for the Prometheus `/metrics` scrape endpoint. Omit to disable. Conventional value: `9179` |
| `graceful_restart_time` | `u16` | `0` | Seconds peers should hold our routes after an unclean session loss (RFC 4724 §3). `0` disables forwarding-state advertisement — peers withdraw our routes immediately. See [Graceful Restart](#graceful-restart-rfc-4724) |
| `restarting` | `bool` | `false` | Set to `true` when restarting pathvectord mid-session to signal the RFC 4724 Restart State (R) bit, so peers stop their stale-route timers as soon as the session re-establishes. Remove after restart. Ignored when `graceful_restart_time = 0` |

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
local_as              = 65002
bgp_id                = "10.0.0.2"
hold_time             = 90
grpc_port             = 50051
metrics_port          = 9179  # Prometheus scrape endpoint; omit to disable
graceful_restart_time = 120   # hold our routes for 120 s on restart

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

## Observability

pathvectord exposes a Prometheus-compatible `/metrics` endpoint for monitoring session
state and RIB sizes. Enable it by adding `metrics_port` to your `[daemon]` config:

```toml
[daemon]
local_as     = 65001
bgp_id       = "10.0.0.1"
metrics_port = 9179
```

On startup you will see:

```
INFO pathvectord: Prometheus metrics listening on http://0.0.0.0:9179/metrics
```

### Metrics reference

| Metric | Type | Labels | Description |
|---|---|---|---|
| `pathvectord_bgp_session_up` | Gauge | `peer` | `1` while the session is Established; `0` otherwise |
| `pathvectord_bgp_session_established_timestamp_seconds` | Gauge | `peer` | Unix timestamp of the most recent session establishment |
| `pathvectord_bgp_adj_rib_in_prefixes` | Gauge | `peer` | Routes received from this peer (Adj-RIB-In size, pre-policy) |
| `pathvectord_bgp_adj_rib_out_prefixes` | Gauge | `peer` | Routes currently advertised to this peer (Adj-RIB-Out size) |
| `pathvectord_bgp_loc_rib_prefixes` | Gauge | `afi` | Best-path routes in Loc-RIB (`afi=ipv4` or `afi=ipv6`) |
| `pathvectord_bgp_sessions_established_total` | Counter | `peer` | Number of times this peer reached Established |
| `pathvectord_bgp_sessions_terminated_total` | Counter | `peer`, `reason` | Session terminations by cause: `unclean`, `notification`, `operator_stop` |
| `pathvectord_bgp_updates_received_total` | Counter | `peer` | BGP UPDATE messages received from this peer |

### Quick check

```bash
curl -s http://localhost:9179/metrics | grep pathvectord
```

Sample output with one peer established and 4 routes received:

```
# HELP pathvectord_bgp_session_up 1 while the session is Established
# TYPE pathvectord_bgp_session_up gauge
pathvectord_bgp_session_up{peer="10.0.0.1"} 1

# TYPE pathvectord_bgp_session_established_timestamp_seconds gauge
pathvectord_bgp_session_established_timestamp_seconds{peer="10.0.0.1"} 1751234567.123

# TYPE pathvectord_bgp_adj_rib_in_prefixes gauge
pathvectord_bgp_adj_rib_in_prefixes{peer="10.0.0.1"} 4

# TYPE pathvectord_bgp_adj_rib_out_prefixes gauge
pathvectord_bgp_adj_rib_out_prefixes{peer="10.0.0.1"} 2

# TYPE pathvectord_bgp_loc_rib_prefixes gauge
pathvectord_bgp_loc_rib_prefixes{afi="ipv4"} 4
pathvectord_bgp_loc_rib_prefixes{afi="ipv6"} 0

# TYPE pathvectord_bgp_sessions_established_total counter
pathvectord_bgp_sessions_established_total{peer="10.0.0.1"} 1

# TYPE pathvectord_bgp_sessions_terminated_total counter
pathvectord_bgp_sessions_terminated_total{peer="10.0.0.1",reason="unclean"} 0

# TYPE pathvectord_bgp_updates_received_total counter
pathvectord_bgp_updates_received_total{peer="10.0.0.1"} 4
```

### Prometheus scrape config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: pathvectord
    static_configs:
      - targets: ["localhost:9179"]
```

### Useful PromQL queries

```promql
# Is any BGP session down?
pathvectord_bgp_session_up == 0

# How long has each session been up? (seconds)
time() - pathvectord_bgp_session_established_timestamp_seconds

# Session flap rate over the last hour
rate(pathvectord_bgp_sessions_terminated_total[1h])

# Routes accepted vs. advertised per peer
pathvectord_bgp_adj_rib_in_prefixes
pathvectord_bgp_adj_rib_out_prefixes

# Total routes in Loc-RIB
sum(pathvectord_bgp_loc_rib_prefixes)
```

### Security note

The `/metrics` endpoint is unauthenticated. In production, bind pathvectord to a
management-only interface or use a firewall rule to restrict scrape access to your
Prometheus server:

```bash
# Allow only the Prometheus server to scrape
ufw allow from <prometheus-ip> to any port 9179
```

### Cardinality note for dynamic peers

Metric series are labeled by peer IP and are **zeroed, not removed**, when a peer is
deconfigured via the `RemovePeer` gRPC call. For a static peer set — the common case for
transit or blackhole upstreams — this has no practical effect. If you add and remove peers
frequently at runtime via the dynamic-peer API, the Prometheus registry will accumulate one
stale zeroed series per removed peer for the lifetime of the process. This is tracked as a
follow-up in `TODO.md`; it is not expected to matter for typical deployments.

---

## RPKI Route Origin Validation

pathvectord can connect to an external RPKI validator over the RTR protocol (RFC 8210,
falling back to RFC 6810) and maintain a live ROA validity cache. Enable it by adding a
`[daemon.rpki]` table:

```toml
[daemon.rpki]
host = "127.0.0.1"
port = 3323
```

`port` defaults to `3323` — [Routinator](https://github.com/NLnetLabs/routinator)'s
default `--rtr` listen port. (Routinator's HTTP status/metrics API defaults to a
different port, `8323` — easy to mix up; double-check whichever validator you're
pointing at.)

**By default, `[daemon.rpki]` filters routes, not just monitors them.** Any route whose
RFC 6811 validity is `Invalid` — a covering ROA exists but names a different origin AS,
or the announcement is more specific than the ROA's max length allows — is rejected on
import, for every configured peer, IPv4 and IPv6. `Valid` and `NotFound` routes are
unaffected. This matches RFC 7115 / BIRD / FRR default convention. Set
`reject_invalid = false` to run RPKI in monitoring-only mode instead (cache still
queryable via `pathvector rpki status`/`validate`, but nothing is filtered):

```toml
[daemon.rpki]
host = "127.0.0.1"
port = 3323
reject_invalid = false  # monitoring only — default is true
```

Connection failures are logged and retried in the background; they never prevent the
daemon from starting or block BGP session processing. Routes accepted before the RTR
client's first successful sync are evaluated against an empty cache (every prefix reads
as `NotFound`, which is accepted) — this is intentional fail-open behavior, matching the
rest of this integration's philosophy, not a gap. RTR sync against a local validator is
typically seconds; a session reset naturally re-evaluates routes once the cache is
populated.

```bash
pathvector rpki status
# RPKI:       enabled
# Connected:  yes
# RTR version: 1
# Serial:     0
# ROA count:  969408
# Last sync:  1782995122

pathvector rpki validate 1.0.0.0/24 13335
# 1.0.0.0/24 origin AS13335: VALID
```

The example above was captured against a real `nlnetlabs/routinator` container with a
live, fully-synced RPKI table (~970k VRPs from all five RIRs) — not synthetic test data.

New to RPKI, or want the full step-by-step walkthrough (including a plain-English
explanation of what problem this solves)? See "Local RPKI interop with Routinator" below.

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
`AddPeer` returns `FAILED_PRECONDITION` if a `RemovePeer` for the same address is still
in progress; poll `ListPeers` until the peer disappears before retrying.

> **Persistence warning:** peers added via `AddPeer` are held in memory only. A daemon
> restart (crash, deploy, `systemctl restart`) loses all dynamically-added peers — the
> daemon starts with only the peers listed in `pathvectord.toml`. Operators running in
> production should either add dynamic peers to the config file after verifying them, or
> use the planned config-file watch feature (tracked in TODO.md) once it ships.

**Side effects of `RemovePeer`:** the daemon clears the peer's Adj-RIB-In, re-runs
best-path selection for every affected prefix, updates the kernel FIB (`RTPROT_BGP`
routes replaced or deleted immediately — live traffic is affected), and sends BGP
WITHDRAW or best-path-change UPDATEs to every other established peer. This all happens
synchronously in the event loop before `RemovePeer` returns, so removing a peer with
a large route table (e.g. a full-table eBGP session) will cause a brief stall in BGP
event processing. See [`pathvector-client/README.md`](../pathvector-client/README.md)
for the full breakdown.

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

## Local RPKI interop with Routinator

A step-by-step walkthrough to see RPKI Route Origin Validation working end-to-end on a
developer machine, against a real, live RPKI dataset — not synthetic test data. If
you're new to RPKI or BGP security, start with the "In plain English" section below
before touching any commands.

### In plain English: what is this, and why would I want it?

BGP — the protocol pathvectord speaks, and the one that decides how traffic finds its
way across the internet — runs almost entirely on trust. When a network announces "I
originate 192.0.2.0/24," other networks mostly just believe it. There's no built-in
mechanism in BGP itself to check whether that announcement is legitimate.

That's exploitable. If someone else announces a prefix they don't own — by mistake or
on purpose — some of the internet's traffic for that prefix can get misdirected to
them instead of the real owner. This is a **BGP hijack**, and it happens in the real
world regularly, sometimes by accident (a router config typo that "leaks" globally)
and sometimes deliberately (traffic interception, denial of service).

**RPKI (Resource Public Key Infrastructure)** lets a prefix's legitimate owner publish
a cryptographically signed statement — a **ROA (Route Origin Authorization)** — of the
form "AS 65001 is authorized to originate 192.0.2.0/24." **Route Origin Validation**
checks incoming BGP routes against the full set of published ROAs and labels each one
`Valid`, `Invalid` (a ROA exists but contradicts this announcement — likely a hijack),
or `NotFound` (no ROA published — common, since RPKI adoption isn't universal, and
treated as "unverifiable" rather than "bad").

Actually validating ROAs requires downloading and cryptographically verifying
certificate chains from RPKI repositories — a big, security-sensitive job of its own.
pathvectord doesn't do this itself. Instead it delegates to a separate program called
an **RPKI validator**, and talks to it over a lightweight protocol called **RTR**
(RPKI-to-Router Protocol). This walkthrough uses
[Routinator](https://github.com/NLnetLabs/routinator), NLnet Labs' open-source
validator, running in Docker.

pathvectord maintains a live, queryable cache of RPKI validity, and — by default —
automatically rejects routes it finds `Invalid` (see `reject_invalid` above). This
walkthrough shows both sides: inspecting the cache directly, and confirming a
misoriginated route actually gets rejected.

### 1. Start Routinator

```bash
docker run -d --name routinator -p 3323:3323 -p 8323:8323 nlnetlabs/routinator:latest
```

Two ports matter here, and it's easy to mix them up:

| Port | Protocol | Used for |
|---|---|---|
| `3323` | RTR (RFC 8210) | What pathvectord actually connects to |
| `8323` | HTTP | Routinator's own status page and metrics — useful for watching progress below, but pathvectord never talks to it |

### 2. Wait for the first sync to complete

On a fresh container, Routinator needs to download and cryptographically verify
certificate chains from all five Regional Internet Registries (ARIN, RIPE, APNIC,
LACNIC, AFRINIC) before it can answer any RTR queries. This commonly takes a few
minutes. Poll its status page until it reports real numbers instead of "ongoing":

```bash
curl -s http://localhost:8323/status
```

```text
Initial validation ongoing. Please wait.
```

...eventually becomes...

```text
version: routinator/0.15.2
serial: 0
valid-roas: 377985
valid-roas-per-tal: afrinic=11791 apnic=48108 arin=223467 lacnic=34017 ripe=60602
vrps: 978014
```

### 3. Configure and start pathvectord

**`rpki-config.toml`:**

```toml
[daemon]
local_as  = 65099
bgp_id    = "10.99.0.1"
bgp_port  = 1179
grpc_port = 51199

[daemon.rpki]
host = "127.0.0.1"
port = 3323
```

No BGP peers are configured here on purpose — this walkthrough is specifically about
the RPKI cache, not a full BGP session. (Combine this `[daemon.rpki]` block with a real
`[[peers]]` section, like the ones in the [GoBGP](#local-interop-with-gobgp) or
[BIRD](#manual-peering-with-bird) walkthroughs above, to see ROV context alongside real
routes.)

```bash
RUST_LOG=info cargo run -p pathvectord -- rpki-config.toml
```

You should see:

```text
INFO pathvectord::daemon: RPKI RTR client started host=127.0.0.1 port=3323
INFO pathvectord::grpc: gRPC management API listening addr=0.0.0.0:51199
```

### 4. Check the cache with the CLI

```bash
cargo run -p pathvector -- --address http://127.0.0.1:51199 rpki status
```

```text
RPKI:       enabled
Connected:  yes
RTR version: 1
Serial:     0
ROA count:  969408
Last sync:  1782995122
```

`Connected: yes` and a non-zero `ROA count` mean pathvectord successfully spoke RTR to
Routinator and has a live copy of (nearly) the whole internet's published ROA set —
almost a million entries, refreshed automatically in the background for as long as the
daemon runs.

### 5. Validate a real, well-known prefix

`1.0.0.0/24`, originated by `AS13335` (Cloudflare — this range backs their `1.1.1.1`
public DNS resolver), has a real, stable ROA you can check against at any time:

```bash
PV="cargo run -p pathvector -- --address http://127.0.0.1:51199"

# The real origin AS — should print VALID.
$PV rpki validate 1.0.0.0/24 13335

# The same prefix, a made-up wrong AS — should print INVALID. A ROA does
# cover this prefix, but it doesn't authorize AS 99999 to originate it.
$PV rpki validate 1.0.0.0/24 99999

# RFC 5737 TEST-NET-1 — reserved for documentation, deliberately never
# allocated or covered by any ROA — should print NOTFOUND.
$PV rpki validate 192.0.2.0/24 65001
```

```text
1.0.0.0/24 origin AS13335: VALID
1.0.0.0/24 origin AS99999: INVALID
192.0.2.0/24 origin AS65001: NOTFOUND
```

Every example on this page was captured against a real Routinator container with a
live, fully-synced RPKI table — not mocked or synthetic data.

### 6. Clean up

```bash
docker stop routinator && docker rm routinator
```

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

**Dynamic peer limitation:** the BGP listener socket is bound once at daemon startup.
Adding a peer with `md5_password` via the `AddPeer` gRPC API only installs the MD5 key
on pathvectord's *outbound* TCP socket (the one used when pathvectord dials the peer).
The inbound listener socket is not re-keyed, so if the remote peer initiates the TCP
connection toward pathvectord, the kernel will reject the handshake because no key is
registered for that source address. Statically configured peers in `pathvectord.toml`
do not have this limitation — their keys are installed before the listener starts.
A full fix requires re-binding the listener socket on each MD5-capable peer add, which
is tracked in TODO.md.

---

## Known issues and limitations

| Feature | Status |
|---|---|
| IPv6 route origination via CLI | `route originate` only accepts IPv4; IPv6 origination works via gRPC directly |
| RFC 7606 revised error handling | Malformed path attributes reset the session instead of being treated as withdrawals |
| BGP port binding | Binding port 179 requires root or `CAP_NET_BIND_SERVICE`; use port 1179 in development |

---

## Graceful Restart (RFC 4724)

### Helper role — preventing route flaps when pathvectord restarts

Configure `graceful_restart_time` to tell upstream peers how long to hold your routes
if your BGP session drops unexpectedly. When restarting pathvectord intentionally, also
set `restarting = true` so peers stop their stale timers as soon as the session comes
back up (remove it after the restart):

```toml
[daemon]
local_as              = 65001
bgp_id                = "10.0.0.1"
graceful_restart_time = 120   # seconds
restarting            = true  # RFC 4724 R-bit — remove after restart completes
```

With this set, pathvectord advertises the RFC 4724 GracefulRestart capability in its
OPEN message with `restart_time = 120` and both IPv4 and IPv6 unicast families marked
`forwarding_preserved`. Peers that support RFC 4724 (GoBGP, BIRD, FRR, most production
routers) will retain your routes as stale entries for up to 120 seconds rather than
immediately withdrawing them.

This is particularly important for **BGP blackhole advertisement** (RFC 7999): if
pathvectord restarts during an active DDoS event, upstream transit peers continue
null-routing the attacked prefix while pathvectord reconnects.

**When to use:**
- Any deployment where route flaps during a daemon restart cause observable impact
- BGP blackhole advertisement where continuity during restarts is operationally critical
- Anywhere upstream peers support RFC 4724 (virtually all modern BGP implementations)

**Recommended values:** 120–300 seconds. The RFC maximum is 4095; values above 4095 are
silently clamped. Setting `graceful_restart_time = 0` (the default) disables
forwarding-state advertisement — peers will receive the GracefulRestart capability
(required for EOR signalling) but withdraw your routes immediately on session loss.

**Why the kernel routes matter:** on Linux, pathvectord installs routes with protocol tag
`RTPROT_BGP`. These routes survive a pathvectord crash and continue forwarding traffic
while the daemon is down. Setting `forwarding_preserved = true` in the capability (which
`graceful_restart_time > 0` does automatically) accurately reflects this: the data plane
is intact even though the control plane is restarting.

### Behavior on restart

When pathvectord starts, it removes all kernel routes it installed in a previous run
(`RTPROT_BGP` protocol tag) before the BGP event loop begins. This prevents stale routes
from persisting indefinitely after an unclean shutdown. The cleanup is logged at startup:

```
INFO removing stale BGP routes v4=42 v6=0
```

> **Note:** stale kernel-route cleanup on startup and the GracefulRestart helper role
> work together. During the restart window, the kernel routes continue forwarding traffic
> (`forwarding_preserved = true`). When pathvectord starts, it cleans them up only after
> new sessions are established and routes are re-installed. Stale-route retention for
> *peer* restarts (RFC 4724 §4.2 speaker role) is not yet implemented.

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

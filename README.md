# pathvector

[![CI](https://github.com/dbrucknr/pathvector/actions/workflows/ci.yml/badge.svg)](https://github.com/dbrucknr/pathvector/actions/workflows/ci.yml)
[![Publish](https://github.com/dbrucknr/pathvector/actions/workflows/publish.yml/badge.svg)](https://github.com/dbrucknr/pathvector/actions/workflows/publish.yml)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![codecov](https://codecov.io/gh/dbrucknr/pathvector/graph/badge.svg)](https://codecov.io/gh/dbrucknr/pathvector)

A production-quality BGP implementation in Rust. Usable as a standalone daemon or
embedded directly into an application.

---

## BGP in 90 seconds

*(Skip this if you already know BGP.)*

The internet is not one network — it is tens of thousands of independent networks
stitched together. Each network is called an **Autonomous System (AS)**: a collection of
IP prefixes under common administrative control. Your ISP is an AS. Google is an AS.

**BGP (Border Gateway Protocol)** is how these ASes tell each other what prefixes they
can reach. It is the routing protocol of the public internet and has been since the early
1990s. BGP-4 is defined in [RFC 4271](https://www.rfc-editor.org/rfc/rfc4271).

BGP is a *path vector* protocol — every route advertisement carries the full sequence of
autonomous systems it has passed through. That sequence is the **AS path**. When you
receive a route, the AS path tells you: "to reach this prefix, packets will travel through
AS 65001, then 65002, then 65003." If your own AS number appears in the path, the route
has looped back — you reject it.

**eBGP** (external) is the session between two routers in *different* ASes. This is what
ISPs use to exchange routes.

**iBGP** (internal) is the session between two routers in the *same* AS. Every BGP
router inside a network must have the same view of the external routing table.

The **three-table RIB model** is how a BGP router organises what it knows:

- **Adj-RIB-In** — one table per peer, routes exactly as received, before any filtering
- **Loc-RIB** — the decision table; import policy filters here, best-path picks a winner
- **Adj-RIB-Out** — one table per peer, routes after export policy, ready to advertise

**Import policy** decides which routes from a peer enter Loc-RIB. **Export policy**
decides which Loc-RIB routes get advertised to each peer. pathvector defaults to
*reject-by-default* for eBGP peers (RFC 8212) — you must explicitly accept routes.

---

## Quick start

**Prerequisites:** Rust ≥ 1.88 and `protoc` ≥ 3 (`brew install protobuf` / `apt install protobuf-compiler`).

```toml
# config.toml — minimal eBGP peer config
[daemon]
local_as = 65002
bgp_id   = "10.0.0.2"   # must be a non-loopback address on this machine

[[peers]]
address        = "10.0.0.1"
remote_as      = 65001
import_default = "accept"   # opt in: accept routes from this peer
export_default = "accept"   # opt in: advertise our routes to this peer
```

```bash
# Build and run the daemon
cargo build --release -p pathvectord
./target/release/pathvectord config.toml

# In another terminal — inspect peers and routes
cargo run -p pathvector -- peer list
cargo run -p pathvector -- route list
cargo run -p pathvector -- dashboard        # live ratatui TUI
```

See [pathvectord/README.md](pathvectord/README.md) for the full configuration reference,
gRPC API, and GoBGP/BIRD interop guide.

---

## Performance

All numbers on Apple M2 Max, release profile.

### MRT replay — real internet table

Replaying a RIPE RIS full-table MRT dump (`latest-bview.gz`, 1.13M IPv4 prefixes)
against a live `pathvectord` over a loopback BGP TCP session.

| Metric | Result | Context |
|---|---|---|
| Prefixes announced | 1,133,510 | Full internet routing table |
| Announcement time | 2.20 s | Wall-clock from first to last UPDATE sent |
| **Announcement throughput** | **514,287 prefixes/sec** | Faster than BIRD 2.x (~100–300k/sec, written in C) |
| Unique path-attribute sets | 168,840 | Attribute deduplication reduces UPDATE message count by ~99% |
| **RIB convergence time** | **2.88 s** | Between BIRD (~2–5s) and GoBGP (~15–30s) |
| Routes accepted into Loc-RIB | 1,133,415 / 1,133,510 | 95 rejected: MRT records multiple peer views per prefix |
| **Total (announce + converge)** | **5.09 s** | End-to-end benchmark time |

To reproduce:

```bash
curl -O https://data.ris.ripe.net/rrc00/latest-bview.gz
just mrt ./latest-bview.gz
```

### Head-to-head vs GoBGP — synthetic stress test

`just stress` runs both daemons (debug profile) on the same host with identical workloads.
`just stress-release` runs both daemons (optimized profile) on the same host with identical workloads — use this for numbers worth recording.

**Convergence time** (lower is better, `just stress-release`):

| Table size | pathvectord | GoBGP | Ratio |
|---|---|---|---|
| 10k  | 0.03 s | 0.05 s | **1.7× faster** |
| 100k | 0.16 s | 0.36 s | **2.3× faster** |
| 250k | 0.27 s | 0.59 s | **2.2× faster** |
| 500k | 0.46 s | 0.93 s | **2.0× faster** |
| 750k | 0.42 s | 0.90 s | **2.1× faster** |
| 900k | 0.27 s | 0.54 s | **2.0× faster** |

**Peak RSS** (lower is better, `just stress-release`):

RSS (resident set size) is the physical RAM the process actually occupies at a given moment.

| Table size | pathvectord | GoBGP | Ratio |
|---|---|---|---|
| 10k  | 15.6 MB  | 51.1 MB  | **3.3× less** |
| 100k | 48.8 MB  | 122.0 MB | **2.5× less** |
| 250k | 144.5 MB | 252.9 MB | **1.7× less** |
| 500k | 279.1 MB | 468.7 MB | **1.7× less** |
| 750k | 313.5 MB | 691.0 MB | **2.2× less** |
| 900k | 334.2 MB | 823.6 MB | **2.5× less** |

Per-route cost at 900k: 0.37 KB (pathvectord) vs 0.91 KB (GoBGP). The RSS plateau
between 750k and 900k reflects attribute interning — real internet routes share a
small set of AS paths and community sets, so marginal cost per route falls as the
table grows.

The numbers above are from `just stress-release`. To reproduce:

```bash
just stress          # debug build — fast to compile, slower numbers
just stress-release  # optimized build — numbers worth recording
```

### Allocator

`pathvectord` and all criterion bench binaries use [jemalloc](https://github.com/jemalloc/jemalloc)
as the global allocator via [`tikv-jemallocator`](https://crates.io/crates/tikv-jemallocator).

BGP control-plane work is allocation-heavy: every route update clones AS paths, community
vectors, and NLRI structs. jemalloc's thread-local magazine caches and aggressive
memory-return behavior reduce fragmentation compared to the system allocator (glibc malloc
on Linux, libmalloc on macOS), which matters for a long-running daemon processing millions
of route events.

Measured improvement vs system allocator on M2 Max (criterion, release profile):

| Benchmark | System alloc | jemalloc | Delta |
|---|---|---|---|
| `loc_rib_insert/10k` | 610 ns | 459 ns | −25% |
| `loc_rib_insert/100k` | 615 ns | 465 ns | −24% |
| `loc_rib_insert/500k` | 1.94 µs | 1.56 µs | −20% |
| `outbound_pipeline/minimal/1` | 274 ns | 174 ns | −37% |
| `outbound_pipeline/dense/1` | 441 ns | 258 ns | −41% |
| `outbound_pipeline/minimal/10` | 1.35 µs | 917 ns | −32% |
| `outbound_pipeline/dense/10` | 2.61 µs | 1.31 µs | −50% |
| `outbound_pipeline/minimal/50` | 6.70 µs | 4.62 µs | −31% |
| `outbound_pipeline/dense/50` | 13.12 µs | 6.17 µs | −53% |
| `select_best/2` | 158 ns | 97 ns | −39% |
| `select_best/10` | 505 ns | 359 ns | −29% |
| `select_best/100` | 2.66 µs | 2.42 µs | −9% |

The outbound pipeline benefits most because each peer advertisement clones the full
attribute set — more allocations per iteration means more leverage from a faster allocator.
`select_best/100` is the floor case: at 100 candidates the comparison work dominates
and allocator choice matters less.

---

## Crate family

Each layer is a separate published crate. A library user can take only the pieces they need.

| Crate | Description | Start here if you want to… |
|---|---|---|
| [`pathvector-types`](pathvector-types) | AS numbers, AS paths, communities, NLRI, path attributes | Understand BGP data structures |
| [`pathvector-policy`](pathvector-policy) | Route policy engine: conditions, actions, term evaluation | Write or test BGP route policies |
| [`pathvector-rib`](pathvector-rib) | Adj-RIB-In, Loc-RIB, Adj-RIB-Out, best-path selection | Understand route decision logic |
| [`pathvector-session`](pathvector-session) | BGP FSM, TCP transport, message codec | Embed BGP session handling in an app |
| [`pathvector-sys`](pathvector-sys) | Linux FIB (rtnetlink) and TCP MD5SIG | Understand kernel integration |
| [`pathvector-bmp`](pathvector-bmp) | BMP receiver (RFC 7854) — **planned** | Monitor a router's routing table passively |
| [`pathvector-client`](pathvector-client) | Typed async Rust client for the gRPC management API | Control the daemon from Rust code |
| [`pathvectord`](pathvectord) | BGP daemon: TOML config, gRPC management API | Run a BGP router |
| [`pathvector`](pathvector) | CLI management tool (`peer`, `route`, `policy`, `dashboard`) | Inspect a running daemon |

Dependency graph (compile-time):

```
pathvector-types
├── pathvector-policy
│   └── pathvector-rib
│       └── pathvectord ──── gRPC (runtime) ──── pathvector-client ──── pathvector (CLI)
└── pathvector-session
    └── pathvectord
pathvector-sys
└── pathvectord
```

---

## Reading guide

| I want to… | Read |
|---|---|
| Run the daemon and configure peers | [pathvectord/README.md](pathvectord/README.md) |
| Use the CLI to inspect peers and routes | [pathvector/README.md](pathvector/README.md) |
| Control the daemon from Rust code | [pathvector-client/README.md](pathvector-client/README.md) |
| Understand BGP session and wire format | [pathvector-session/README.md](pathvector-session/README.md) |
| Understand the three-table RIB and best-path | [pathvector-rib/README.md](pathvector-rib/README.md) |
| Write or test a route policy | [pathvector-policy/README.md](pathvector-policy/README.md) |
| Understand BGP types (ASN, community, NLRI) | [pathvector-types/README.md](pathvector-types/README.md) |
| Understand Linux FIB / TCP MD5 integration | [pathvector-sys/README.md](pathvector-sys/README.md) |
| Benchmark with a real internet table | [pathvector-mrt/README.md](pathvector-mrt/README.md) |
| Contribute code | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Understand the test strategy | [TESTING.md](TESTING.md) |

---

## Docker

```bash
docker pull ghcr.io/dbrucknr/pathvector:latest
```

To peer pathvectord with GoBGP in Docker, save this as `Dockerfile.gobgp`:

```dockerfile
FROM alpine

RUN wget -q https://github.com/osrg/gobgp/releases/download/v4.6.0/gobgp_4.6.0_linux_amd64.tar.gz \
    && tar xf gobgp_4.6.0_linux_amd64.tar.gz \
    && rm gobgp_4.6.0_linux_amd64.tar.gz

EXPOSE 179 50051

CMD ["./gobgpd", "--log-level=info", "--config-file=/gobgp.conf"]
```

> This Dockerfile hardcodes `linux_amd64`. On Apple Silicon, Docker Desktop
> runs Linux/amd64 under emulation by default, so this works — but it will be
> slower than a native arm64 build.

Then a `docker-compose.yml` that wires them together:

```yaml
services:
  pathvectord:
    image: ghcr.io/dbrucknr/pathvector:latest
    volumes:
      - ./config.toml:/etc/pathvectord/config.toml:ro
    command: ["/etc/pathvectord/config.toml"]
    ports:
      - "51200:51200"   # gRPC management API
    cap_add:
      - NET_ADMIN       # required for kernel route installation (RTPROT_BGP)
    networks:
      - bgp
    depends_on:
      - gobgp

  gobgp:
    build:
      context: .
      dockerfile: Dockerfile.gobgp
    volumes:
      - ./gobgp.conf:/gobgp.conf:ro
    networks:
      - bgp

networks:
  bgp:
    driver: bridge
```

With a minimal `gobgp.conf`:

```toml
[global.config]
  as        = 65001
  router-id = "1.0.0.1"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "pathvectord"   # Docker DNS resolves the service name
    peer-as          = 65002
  [neighbors.transport.config]
    passive-mode = true
```

And `config.toml` for pathvectord pointing at the GoBGP container:

```toml
[daemon]
local_as  = 65002
bgp_id    = "10.0.0.2"
grpc_port = 51200

[[peers]]
address        = "gobgp"   # Docker DNS resolves the service name
remote_as      = 65001
import_default = "accept"
export_default = "accept"
```

> `NET_ADMIN` is only needed for FIB (kernel routing table) updates. Omit it if
> you are using pathvectord purely as a route collector or policy engine.

---

## Testing

The test suite combines seven layers: unit tests, compiled documentation examples,
property-based tests (proptest), fuzz targets on the codec decode path, ratatui snapshot
tests for the TUI dashboard, Docker-based end-to-end tests against a real GoBGP peer,
and dependency-inversion tests that exercise every CLI subcommand through
`MockDaemonClient` without a live daemon.

```bash
just ci          # unit + property + doc tests, clippy, fmt, MSRV — no Docker required
just e2e         # Docker-based end-to-end suite against a real GoBGP peer
just lint-linux  # run clippy inside a Linux container (catches macOS blind spots)
```

See [TESTING.md](TESTING.md) for the full description of each layer.

---

## Use cases

**Full BGP daemon** — run `pathvectord` on a Linux server and peer with upstream
providers or route reflectors.

**Embedded BGP speaker** — link `pathvector-session` and `pathvector-types` directly
into an application. Useful for load balancers advertising VIPs, or Kubernetes nodes
announcing pod CIDRs.

**BGP monitoring** — deploy `pathvector-bmp` (planned) as a standalone BMP collector to
receive and inspect route updates from existing routers without participating in routing.

**Policy testing** — use `pathvector-policy` in isolation to validate and unit-test BGP
route policies before deploying them to production.

---

## Ecosystem

pathvector builds on two standalone foundation crates:

- [`ipnetx`](https://crates.io/crates/ipnetx) — set algebra on IP address space (union, intersection, difference)
- [`routemap`](https://crates.io/crates/routemap) — in-memory longest-prefix-match table via stride-4 treebitmap

Both are independently published and have no dependency on pathvector.

---

## Status

Active development. Crates are not yet published to crates.io.

| Crate | Status | Notes |
|---|---|---|
| `pathvector-types` | Stable | Newtypes, AS path, communities, NLRI, all path attributes |
| `pathvector-policy` | Stable | Prefix-list, community, AS-path, local-pref, MED conditions and actions |
| `pathvector-rib` | Stable | Full three-table RIB; best-path steps 2–7, 9–10; LPM forwarding queries |
| `pathvector-session` | Stable | Full BGP FSM; all five message types; 4-byte ASN; GoBGP-validated |
| `pathvector-client` | Stable | Typed async Rust client wrapping all gRPC services |
| `pathvectord` | Active | Full BGP speaker; gRPC management API; dynamic peer add/remove; GoBGP-validated |
| `pathvector` | Active | CLI: peer/route/policy/origination subcommands; live ratatui dashboard |
| `pathvector-bmp` | Planned | BMP receiver for passive route monitoring |

---

## License

MIT — see [LICENSE](LICENSE).

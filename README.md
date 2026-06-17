# pathvector

[![CI](https://github.com/dbrucknr/pathvector/actions/workflows/ci.yml/badge.svg)](https://github.com/dbrucknr/pathvector/actions/workflows/ci.yml)
[![Publish](https://github.com/dbrucknr/pathvector/actions/workflows/publish.yml/badge.svg)](https://github.com/dbrucknr/pathvector/actions/workflows/publish.yml)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![codecov](https://codecov.io/gh/dbrucknr/pathvector/graph/badge.svg)](https://codecov.io/gh/dbrucknr/pathvector)

A production-quality BGP implementation in Rust. Fast, memory-efficient, and designed as a library-first stack — usable as a full daemon or embedded directly into an application.

BGP is formally classified as a *path vector* routing protocol, the only widely deployed one at internet scale.

---

## Quick start

**Prerequisites:** Rust ≥ 1.88 and `protoc` ≥ 3 (`brew install protobuf` / `apt install protobuf-compiler`).

```toml
# config.toml — minimal eBGP peer config
[daemon]
local_as = 65002
bgp_id   = "10.0.0.2"

[[peers]]
address   = "10.0.0.1"
remote_as = 65001
```

```bash
# Build and run the daemon
cargo build --release -p pathvectord
./target/release/pathvectord config.toml

# In another terminal — inspect peers and routes via the CLI
cargo run -p pathvector -- peer list
cargo run -p pathvector -- route list
cargo run -p pathvector -- dashboard        # live ratatui TUI
```

See [DAEMON.md](DAEMON.md) for the full configuration reference and gRPC API examples.
See [CLI.md](CLI.md) for all subcommands and the policy reload workflow.

---

## Docker

A pre-built image is published to the GitHub Container Registry on every merge to `main`:

```bash
docker pull ghcr.io/dbrucknr/pathvector:latest
```

The image requires a config file mounted at startup. A minimal `docker-compose.yml`
that peers pathvectord with a GoBGP instance on the same bridge network:

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

  gobgp:
    image: ghcr.io/dbrucknr/pathvector-gobgpd-test:latest
    networks:
      - bgp

networks:
  bgp:
    driver: bridge
```

> **Note:** `NET_ADMIN` is only needed for FIB (kernel routing table) updates.
> If you are using pathvectord purely as a route collector or policy engine you
> can omit it.

> **Platform:** the published image is `linux/amd64` only. The daemon peers and
> exchanges routes correctly on any platform but will not install routes into the
> host kernel on macOS Docker Desktop (no Linux FIB available).

---

## Crate family

The implementation is split into focused, independently published crates. Each layer depends only on those below it.

| Crate | Description |
|---|---|
| [`pathvector-types`](pathvector-types) | AS numbers, AS paths, communities, NLRI, and route attributes |
| [`pathvector-policy`](pathvector-policy) | Route policy engine: prefix-list, community, and AS path match/action |
| [`pathvector-rib`](pathvector-rib) | Adj-RIB-In, Loc-RIB, Adj-RIB-Out, and best-path selection |
| [`pathvector-session`](pathvector-session) | BGP FSM, TCP transport, and message codec |
| [`pathvector-bmp`](pathvector-bmp) | BMP receiver (RFC 7854): route monitoring and peer state |
| [`pathvector-client`](pathvector-client) | Typed async Rust client for the gRPC management API |
| [`pathvectord`](pathvectord) | BGP daemon: TOML config and gRPC management API |
| [`pathvector`](pathvector) | CLI management tool (`pathvector peer`, `route`, `policy`, `dashboard`) |

Dependency flow (compile-time crate graph):

```
pathvector-types
├── pathvector-policy
│   └── pathvector-rib
│       └── pathvectord ──── gRPC API (runtime) ──── pathvector-client
│                                                          └── pathvector (CLI)
└── pathvector-session
    └── pathvectord
```

---

## Use cases

**Full BGP daemon** — run `pathvectord` on a Linux server and peer with upstream providers or route reflectors.

**Embedded BGP speaker** — link `pathvector-session` and `pathvector-types` directly into an application. Useful for load balancers advertising VIPs, or Kubernetes nodes announcing pod CIDRs.

**BGP monitoring** — deploy `pathvector-bmp` as a standalone BMP collector to receive and inspect route updates from existing routers without participating in the routing protocol.

**Policy testing** — use `pathvector-policy` in isolation to validate and unit-test BGP route policies before deploying them to production.

---

## Ecosystem

pathvector builds on two standalone foundation crates:

- [`ipnetx`](https://crates.io/crates/ipnetx) — set algebra on IP address space (union, intersection, difference, complement)
- [`routemap`](https://crates.io/crates/routemap) — in-memory longest-prefix-match table via stride-4 treebitmap

These crates are independently useful and published separately. pathvector depends on them but they have no dependency on pathvector.

---

## Performance

Measured by replaying a real RIPE RIS full-table MRT dump (`latest-bview.gz`, 1.13M IPv4 prefixes) against a live `pathvectord` instance over a loopback BGP TCP session on Apple M2 Max.

| Metric | Result |
|---|---|
| Prefixes announced | 1,133,510 |
| Announcement time | 3.30 s |
| **Announcement throughput** | **343,920 prefixes/sec** |
| Unique path-attribute sets | 168,840 |
| **RIB convergence time** | **3.70 s** |
| Routes accepted into Loc-RIB | 1,133,415 / 1,133,510 (99.99%) |
| **Total (announce + converge)** | **7.00 s** |

Announcement throughput is on par with BIRD 2.x (~100–300k prefixes/sec). RIB convergence of 6.78s for a full internet table falls between BIRD (2–5s, written in C) and GoBGP (~15–30s). The 95 rejected prefixes are expected: the MRT dump records multiple peer perspectives per prefix and only the best-path winner enters Loc-RIB.

To reproduce:

```bash
# Download a RIPE RIS full-table snapshot (~90 MB)
curl -O https://data.ris.ripe.net/rrc00/latest-bview.gz

# Build, start pathvectord, run the MRT replayer
just mrt ./latest-bview.gz
```

---

## Status

Active development. Crates are not yet published to crates.io.

| Crate | Status | Notes |
|---|---|---|
| `pathvector-types` | Stable | Newtypes, AS path, communities, NLRI, all path attributes |
| `pathvector-policy` | Stable | Prefix-list, community, AS-path, local-pref, MED conditions and actions |
| `pathvector-rib` | Stable | Full three-table RIB; best-path steps 2, 4–7, 10; LPM forwarding queries |
| `pathvector-session` | Stable | Full BGP FSM; all five message types; 4-byte ASN; GoBGP-validated |
| `pathvector-client` | Stable | Typed async Rust client wrapping all three gRPC services |
| `pathvectord` | Active | Full BGP speaker; gRPC management API; GoBGP-validated |
| `pathvector` | Active | CLI: peer/route/policy subcommands; live ratatui dashboard |
| `pathvector-bmp` | Planned | BMP receiver for passive route monitoring |

---

## Testing

pathvector takes correctness seriously. The test suite combines seven layers: unit tests, compiled documentation examples, property-based tests (proptest), fuzz targets on the codec decode path, ratatui snapshot tests for the TUI dashboard, Docker-based end-to-end tests against a real GoBGP peer, and dependency-inversion tests that exercise every CLI subcommand through `MockDaemonClient` without a live daemon. See [TESTING.md](TESTING.md) for the full description of each layer and how to run them.

```sh
just ci          # unit + property + doc tests, clippy, fmt, MSRV — no Docker required
just e2e         # Docker-based end-to-end suite against a real GoBGP peer
just install-hooks  # install the pre-push hook (run once after cloning)
```

The pre-push hook runs `just e2e` automatically before each push. Skip it for a specific push with `git push --no-verify`.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the runtime data flow and crate design.

---

## License

MIT — see [LICENSE](LICENSE).

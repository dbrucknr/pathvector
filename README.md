# pathvector

[![CI](https://github.com/dbrucknr/pathvector/actions/workflows/ci.yml/badge.svg)](https://github.com/dbrucknr/pathvector/actions/workflows/ci.yml)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

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

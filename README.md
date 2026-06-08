# pathvector

[![CI](https://github.com/dbrucknr/pathvector/actions/workflows/ci.yml/badge.svg)](https://github.com/dbrucknr/pathvector/actions/workflows/ci.yml)

A production-quality BGP implementation in Rust. Fast, memory-efficient, and designed as a library-first stack — usable as a full daemon or embedded directly into an application.

BGP is formally classified as a *path vector* routing protocol, the only widely deployed one at internet scale.

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
| [`pathvectord`](pathvectord) | BGP daemon: TOML config, CLI, and management API |

Dependency flow:

```
pathvectord
├── pathvector-session
├── pathvector-rib
│   ├── pathvector-policy
│   │   ├── pathvector-types
│   │   ├── ipnetx
│   │   └── routemap
│   └── pathvector-types
├── pathvector-bmp
│   └── pathvector-types
└── pathvector-types
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
| `pathvector-bmp` | Not started | — |
| `pathvectord` | Active | Full BGP speaker; gRPC management API; GoBGP-validated |

See [DAEMON.md](DAEMON.md) for build instructions, configuration reference, and how to query the gRPC management API.

---

## Testing

pathvector takes correctness seriously. The test suite combines unit tests, compiled documentation examples, property-based tests, and line coverage measurement. See [TESTING.md](TESTING.md) for a full description of the testing philosophy, patterns, and how to run the suite.

If you'd like to run all the CI tests locally, use `just ci`.

---

## License

MIT

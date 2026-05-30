# pathvector

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

Early development. Crates are not yet published to crates.io.

| Crate | Status |
|---|---|
| `pathvector-types` | In progress |
| `pathvector-policy` | Planned |
| `pathvector-rib` | Planned |
| `pathvector-session` | Planned |
| `pathvector-bmp` | Planned |
| `pathvectord` | Planned |

---

## License

MIT

# TODO

Tracked items that are intentionally deferred — known gaps, planned features,
and protocol steps that require components not yet built. Each entry notes
which crate it belongs to and why it was deferred.

- Add cargo fuzz, make sure to include proptest for each module. It's missing

---

## General
Download Relevant RFC's to each module.
Generate a list of requirements from the RFC's.
Check whether or not the each module currently meets these requirements.

Add cargo fuzz testing to each module.
- Should help us catch bugs, and possible security vulnerabilities.
- We want to try to guarantee our system doesn't panic.

Tests e2e
  - We will use the RFC's to generate test cases for each module.
  - I think the RFC's should provide .conf files (or otherwise) to define test scenarios. They will try to cover the requirements
    specified in the RFC's.
- We should also try and simulate adversarial inputs to the daemon to ensure it can handle unexpected situations.

## pathvector-rib

### Best-path selection — missing decision steps

RFC 4271 §9.1 defines a 10-step decision process. The current implementation
covers steps 2, 4, 5, 6, and 10. The remaining steps are deferred because
they require information the RIB layer does not yet have.

| Step | Criterion | Blocked on |
|---|---|---|
| 1 | Prefer routes with a reachable next-hop | IGP integration — the RIB needs to know which next-hops are reachable via the interior routing protocol |
| 3 | Prefer locally originated routes | Peer session type — the RIB needs to know whether a route was originated locally (`network` statement) vs learned from a peer |
| 7 | Prefer eBGP over iBGP | Peer session type — the session layer must tag routes with the session type (internal vs external) when inserting into the RIB |
| 8 | Prefer lowest IGP metric to next-hop | IGP integration — requires the router's own IGP topology view |
| 9 | Prefer oldest eBGP route | Route age tracking — the RIB would need to record when each route was first received |

### Longest-prefix-match queries

The current `LocRib` uses `HashMap<Nlri<A>, _>` keyed on exact prefixes.
Real BGP implementations support longest-prefix-match queries (e.g. "which
route covers `10.1.2.3`?") for forwarding decisions.

Switch to [`routemap`](https://crates.io/crates/routemap) (already in the
workspace dependencies) for the `best` map in `LocRib` to enable O(log n)
LPM lookups.

### Multi-path (ECMP)

Best-path selection currently picks exactly one winner. BGP ECMP
(equal-cost multi-path) allows multiple routes to be installed simultaneously
when their path cost is equal up to and including step 8. Requires a
`MultiPath` variant in the best-route representation and configuration to
enable (`maximum-paths` knob).

### Route reflector support

Intra-cluster route reflection (RFC 4456) requires the RIB to track:
- `ORIGINATOR_ID` (type 9) — the router-id of the originating route reflector client
- `CLUSTER_LIST` (type 10) — the sequence of cluster IDs the route has passed through

Loop prevention in a route reflector topology uses these attributes instead
of (or in addition to) the AS path.

### Configurable MED behaviour

The current implementation treats missing MED as `0`. Real implementations
offer:
- `always-compare-med` — compare MED even when routes come from different ASes
- `deterministic-med` — group routes by originating AS before comparing MED,
  ensuring the same best path is chosen regardless of route arrival order
- Configurable missing-MED treatment (`0`, `u32::MAX`, or policy-set)

---

## pathvector-session

### Done

- Message codec: OPEN, UPDATE, KEEPALIVE, NOTIFICATION, ROUTE-REFRESH
- NLRI parser: variable-length prefix encoding for IPv4 and IPv6
- MP_REACH_NLRI / MP_UNREACH_NLRI for multiprotocol routes
- 4-byte ASN capability — codec encoding/decoding, `AS_TRANS` substitution in FSM, `AS4_PATH` / `AS4_AGGREGATOR` handling
- Graceful Restart and Route Refresh capability — codec parsing and encoding
- BGP FSM: Idle → Connect → Active → OpenSent → OpenConfirm → Established (pure state machine, no I/O)
- Codec error logging in transport — `recv_message` errors are now surfaced via `tracing::warn!` before dropping the connection
- **GoBGP interoperability validated (2026-05-31)** — full session lifecycle confirmed: OPEN negotiation, KEEPALIVE exchange, UPDATE announce and withdraw, session teardown

### Remaining

- MD5 authentication (RFC 2385) — TCP-MD5 socket option for eBGP peering
- BGP-SEC (RFC 8205) — cryptographic path validation; further out, but worth noting alongside MD5 as the broader authentication story
- Connection collision detection — when both peers dial simultaneously, the router with the higher BGP ID keeps its outbound connection; FSM has the `bgp_id` field but no collision logic
- Graceful Restart FSM behaviour (RFC 4724) — capability is parsed and forwarded in `SessionInfo`, but the FSM does not yet act on it (hold forwarding state, stale route timer)

---

## pathvector-bmp

Not yet started. Key work items:

- BMP receiver (RFC 7854): Route Monitoring, Stats Reports, Peer Up/Down messages
- Route Monitoring NLRI → `Route<A>` → `AdjRibIn` pipeline
- Per-peer RIB view reconstruction from BMP stream

---

## pathvectord

### Done

- TOML configuration: `local_as`, `bgp_id`, `hold_time`, per-peer `address`/`port`/`remote_as`
- Session spawning: one `transport::spawn()` task per configured peer, events multiplexed into a single channel
- RIB integration: `UpdateMessage` → `Route<Ipv4Addr>` conversion, `LocRib` insert/withdraw/peer-teardown
- Structured logging via `tracing` with `RUST_LOG` env-filter support
- **GoBGP interoperability validated (2026-05-31)**

### Remaining

- gRPC management API — define `.proto` schema for:
  - Peer state queries (session state, uptime, prefixes received/advertised)
  - RIB queries (show route, show best path, show candidates)
  - Policy introspection
  - Runtime policy reload
- Import policy — apply `pathvector-policy` to routes before `LocRib::insert`; currently all received routes are accepted unconditionally
- `AdjRibIn` — add pre-policy store per peer to support soft reconfiguration without requiring a full session reset
- CLI binary (`pathvector`) using the gRPC client
- Docker image: `FROM debian:slim`, single binary, config file mount, gRPC port exposed

---

## pathvector-client

Not yet started. To be added to the workspace when the gRPC management API
schema is finalised. Will contain generated client stubs so users and the
`pathvector` CLI can talk to `pathvectord` with a typed Rust API.

---

## Cross-cutting

- CI pipeline: `cargo test`, `cargo clippy`, `cargo doc`, MSRV check (1.86)
- Integration test isolation — `tests/transport.rs` binds real loopback TCP sockets; these tests are excellent for correctness but will be slow and port-conflict-prone on shared CI runners; consider a `#[cfg(not(ci))]` guard or dedicated test binary with a randomised port range
- Fuzz testing for the session codec (OPEN/UPDATE parsing are attack surface)
- Benchmark suite for `LocRib` insert/best-path under realistic prefix volumes
  (100k IPv4 prefixes, M2 Max baseline)

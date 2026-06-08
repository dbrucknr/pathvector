# TODO

Tracked items that are intentionally deferred — known gaps, planned features,
and protocol steps that require components not yet built. Each entry notes
which crate it belongs to and why it was deferred.

---

## General
~~Download Relevant RFC's to each module.~~
~~Generate a list of requirements from the RFC's.~~
~~Check whether or not the each module currently meets these requirements.~~
**Done** — `RFC_REQUIREMENTS.md` tracks every implemented RFC, its requirements, owning module,
implementation status, and verified-by test citations.

### Property testing and fuzz coverage (ordered)

Proptests and fuzzing serve different purposes and should be added in this order:

- **Proptests** prove structural invariants hold for all valid inputs — RFC conformance evidence.
- **Cargo fuzz** proves arbitrary byte input never panics or corrupts state — panic-safety story.

**Phase 1 — `pathvector-session` codec round-trips** ✓ Done
All four message types (OPEN, UPDATE, NOTIFICATION, KEEPALIVE, ROUTE-REFRESH) have round-trip
proptests at both the `BgpMessage::encode/decode` layer (`message/prop_tests.rs`) and the
`BgpCodec` framing layer (`framing/prop_tests.rs`). Full capabilities, path attributes, and all
`NotificationError` sub-families are exercised. `prop_decode_never_panics` covers both layers.
The generators exposed a real round-trip constraint: `Unknown` sub-variants must exclude codes that
the decoder maps to named variants — constrained accordingly.

**Phase 2 — `pathvector-rib` best-path invariants** ✓ Done
Step-by-step isolation proptests for every implemented decision step:
- `prop_select_best_winner_has_highest_local_pref` (step 2)
- `prop_select_best_winner_has_shortest_as_path` (step 4)
- `prop_select_best_winner_has_lowest_origin` (step 5)
- `prop_select_best_winner_has_lowest_med` (step 6)
- `prop_select_best_ebgp_beats_ibgp` (step 7)
- `prop_select_best_winner_is_in_candidates`, `prop_select_best_non_empty_returns_some`,
  `prop_select_best_deterministic` (structural invariants)
- LocRib, AdjRibIn, and AdjRibOut structural proptests (insert/withdraw/consistency)

**Phase 3 — `pathvector-policy` semantics** ✓ Done
Empty-policy default action, catch-all terms, and all-Next fall-through were already covered.
Added the two remaining plan items:
- `prop_policy_evaluation_is_deterministic`: same route state evaluated twice always produces
  the same decision — rules out hidden mutable state in Policy or its terms.
- `prop_first_match_wins_accept_blocks_later_reject`: a route matched by term N (Accept)
  is never passed to term N+1 (catch-all Reject) — core first-match-wins guarantee.
Also covers 8 action invariants (PrependAsPath, Add/Remove/SetCommunities, SetLocalPref,
AnyCondition, ActionSequence).

**Phase 4 — `cargo fuzz` on the codec decode path** ✓ Done
Two fuzz targets live in `fuzz/fuzz_targets/` at the workspace root:
- `session_framing` — feeds raw `&[u8]` into `BgpCodec::decode` (the entry point for any remote peer byte stream);
  if the framing layer accepts a frame, the round-trip encode/decode is also exercised.
- `session_message` — patches the 2-byte length field so `BgpMessage::decode` receives a self-consistent
  buffer regardless of the fuzz input, driving the body-parsing paths for all five message types.

Seed corpus (`fuzz/corpus/session_{framing,message}/`) pre-populates valid KEEPALIVE, OPEN (minimal and
with 4-byte ASN capability), NOTIFICATION, UPDATE, and ROUTE-REFRESH examples so the fuzzer
starts from real message boundaries rather than discovering the `0xFF×16` marker pattern cold.

Both targets compile clean under nightly and ran ~3M executions / 16 seconds with zero panics on
first smoke run. Run via the Justfile from the workspace root:

```sh
just fuzz-smoke     # 60 s smoke run of both targets
just fuzz-framing   # extended run until Ctrl-C
just fuzz-message   # extended run until Ctrl-C
```

See TESTING.md for the full explanation of the nightly/Homebrew PATH issue and crash reproduction.

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
| 8 | Prefer lowest IGP metric to next-hop | IGP integration — requires the router's own IGP topology view |
| 9 | Prefer oldest eBGP route | Route age tracking — the RIB would need to record when each route was first received |

### Longest-prefix-match queries

**Done.** `LocRib::best` now uses `RouteMap<A, (PeerId, Route<A>)>` (routemap 0.1.2)
instead of `HashMap`. `LocRib::longest_match(addr: A)` exposes O(log n) LPM
for forwarding lookups. Exact-prefix queries (`best`, `best_peer`) use the new
`RouteMap::get` added in routemap 0.1.2.

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
- **Outbound UPDATE send path (2026-06-01)** — `SessionHandle::update_sender()` returns a cloneable `mpsc::Sender<UpdateMessage>`. `wait_for_input()` wraps its `select!` in a `loop` with a lowest-priority arm that writes outbound UPDATEs directly to the TCP framer inline; write failures return `TcpFailed` to the FSM for clean recovery.

### Remaining

- MD5 authentication (RFC 2385) — TCP-MD5 socket option for eBGP peering
- BGP-SEC (RFC 8205) — cryptographic path validation; further out, but worth noting alongside MD5 as the broader authentication story
- Connection collision detection — when both peers dial simultaneously, the router with the higher BGP ID keeps its outbound connection; FSM has the `bgp_id` field but no collision logic
- Graceful Restart FSM behaviour (RFC 4724) — capability is parsed and forwarded in `SessionInfo`, but the FSM does not yet act on it (hold forwarding state, stale route timer)

### Panic safety — replace `expect()` in `build_session_info`

**Done.** `build_session_info` now returns `Option<SessionInfo>`. The `on_open_confirm`
Keepalive arm uses `let...else`: on `None` it logs `tracing::error!`, resets the FSM
to Idle, and returns `[StopHoldTimer, StopKeepaliveTimer, CloseTcpConnection]` — the
same clean teardown as a normal failure, without panicking or leaving stale routes.
Covered by `test_keepalive_in_open_confirm_with_missing_peer_open_resets_to_idle`.

### Transport layer mocking via `BgpTransport` trait — **Done**

`BgpTransport` is a public trait (RPITIT + `+ Send` bounds) in `transport/mod.rs`.
`FramedBgpTransport` is the production impl wrapping `FramedRead`/`FramedWrite` over TCP.
`Session<T: BgpTransport>` is generic; `spawn()` stays non-generic (`Session<FramedBgpTransport>`).
`spawn_with<T: BgpTransport>` (`#[cfg(test)]`) injects a pre-built transport; the first
`InitiateTcpConnect` output activates it and queues `TcpConnected` via `pending_input`,
bypassing real TCP. Two previously-uncovered write-failure paths are now covered:
- `test_send_failure_in_execute_triggers_tcp_failed_recovery` — OPEN send fails before
  Established; `execute` returns false, `run` feeds `TcpFailed`.
- `test_outbound_update_write_failure_emits_terminated` — UPDATE write fails after
  Established; the UPDATE arm in `wait_for_input` returns `TcpFailed`, teardown emits
  `Terminated`.

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
- **Outbound advertisement path (2026-06-01)** — pathvectord is now a full BGP speaker:
  - `ExportDefault` config enum and per-peer `export_default` field (mirrors `import_default`)
  - Per-peer export policies evaluated via `propagate_prefix` before `AdjRibOut` insertion
  - `prepare_outbound` applies eBGP attribute transforms: prepend local AS to `AS_PATH`, rewrite `NEXT_HOP` to local BGP ID, strip `LOCAL_PREF`
  - `route_to_update` / `withdraw_msg` serialise `AdjRibOut` changes to wire-format `UpdateMessage`
  - On `Established`: `AdjRibOut` reset to clean slate, full-table dump to the new peer
  - On `RouteUpdate`: affected NLRIs propagated to all established peers after `handle_update`
  - On `Terminated`: snapshot-before-withdraw pattern propagates best-path changes to other established peers; `AdjRibOut` reset for clean reconnect
  - Idempotent: `propagate_prefix` compares new route against what is already in `AdjRibOut` and sends UPDATE/WITHDRAW only when the advertised state actually changes

### Remaining

- **Panic safety in main event loop — Done.** All `expect()` calls in `run()` replaced with
  `let...else` + `tracing::error!` + `continue`. Unknown peer IPs now log an error and skip
  the event rather than panicking the daemon.

- Soft reconfiguration → export propagation — `reapply_import_policy` changes which routes
  are in `LocRib`, but does not currently trigger `propagate_prefix` to update peers. Callers
  that perform policy reloads must trigger outbound propagation manually until this is wired.

- IPv6 in the daemon — the session layer already speaks IPv6 via MP_REACH_NLRI, but
  `pathvectord` is hardcoded to `Route<Ipv4Addr>`. Extending to IPv6 requires a
  dual-stack RIB or a generic event dispatch on address family.
  **IPv4 MP path done (2026-06-08):** `handle_update` now processes `MP_UNREACH_NLRI`
  and `MP_REACH_NLRI` attributes for AFI/SAFI=IPv4 unicast. Peers that send IPv4
  withdrawals or announcements via the multiprotocol attributes instead of the
  traditional fields are handled correctly. Non-IPv4 AFI/SAFIs are logged at DEBUG
  and skipped. Full IPv6 RIB support still requires the dual-stack work above.

- gRPC management API — **Done (2026-06-08).** `PeerService` and `RibService` are live on a configurable port (default 50051). Proto schema at `proto/pathvector/v1/management.proto`. See [DAEMON.md](DAEMON.md) for the full operational guide and `grpcurl` query examples. Remaining: policy introspection and runtime policy reload (blocked on wiring `reapply_import_policy` to export propagation).
- Import policy — **Done.** `handle_update` now evaluates a `Policy<Route<Ipv4Addr>>` per route before `LocRib::insert`; routes that return `Reject` are dropped. Per-peer default action (`import_default = "accept"` / `"reject"`) is configurable in TOML; eBGP peers default to `"reject"` (RFC 8212) when omitted, iBGP peers default to `"accept"`. The infrastructure is in place for adding `Term` conditions (prefix lists, community filters, etc.).
- BLACKHOLE community discard action (RFC 7999) — `Community::BLACKHOLE` (0xFFFF029A) is defined and detectable via `is_blackhole()`, but there is no null-route or discard action wired in the RIB or daemon; routes tagged with BLACKHOLE should have traffic to their prefix dropped at the forwarding plane
- `AdjRibIn` — **Done.** Per-peer `AdjRibIn` tables are built at startup and wired through `handle_update`. Raw (pre-policy) routes are stored on every announcement; withdrawals remove from both `AdjRibIn` and `LocRib`; session teardown calls `AdjRibIn::clear()`. `reapply_import_policy` re-evaluates all stored raw routes against a new policy, inserting accepted routes and withdrawing rejected ones from `LocRib` without a session reset.
- CLI binary (`pathvector`) using the gRPC client
- Docker image: `FROM debian:slim`, single binary, config file mount, gRPC port exposed

---

## pathvector-client

Not yet started. To be added to the workspace when the gRPC management API
schema is finalised. Will contain generated client stubs so users and the
`pathvector` CLI can talk to `pathvectord` with a typed Rust API.

---

## Cross-cutting

- CI pipeline: `cargo test`, `cargo clippy`, `cargo doc`, MSRV check (1.88) — **Done.** `.github/workflows/ci.yml` has five jobs: `test` (stable), `lint` (clippy + rustfmt, stable), `msrv` (1.88), `docs` (stable, `-D warnings`), and `fuzz` (nightly, `just fuzz-smoke`). A `Justfile` at the workspace root provides matching local recipes so CI and development use the same commands. All jobs install `protoc` (required by `pathvectord`'s gRPC codegen build script).
- Integration test isolation — `tests/transport.rs` binds real loopback TCP sockets; these tests are excellent for correctness but will be slow and port-conflict-prone on shared CI runners; consider a `#[cfg(not(ci))]` guard or dedicated test binary with a randomised port range
- Fuzz testing — tracked as Phase 4 in the property testing section above
- Benchmark suite for `LocRib` insert/best-path under realistic prefix volumes
  (100k IPv4 prefixes, M2 Max baseline)

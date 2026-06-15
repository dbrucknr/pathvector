# TODO

Tracked items that are intentionally deferred — known gaps, planned features,
and protocol steps that require components not yet built. Each entry notes
which crate it belongs to and why it was deferred.

---

## Prioritized next steps

Items are grouped by what they unlock, not just by effort. A small correctness
fix that unblocks a larger feature is worth doing before the feature itself.

### Tier 3 — Larger scope, important but not blocking

**9. Arista cEOS (commercial, later)**
cEOS is Arista's containerized EOS, freely available with registration from the
Arista portal. Runs as a proper OCI container. Most accessible commercial router OS
for interop testing — no VM required.

Add once BIRD and FRR are solid. Requires an Arista account; cannot be pulled
anonymously in public CI. Gate behind a `CI_ARISTA_IMAGE` env var so it runs only
when the image is available.

**11. Adversarial input / NOTIFICATION path testing**
RFC 7606 (item 3) is the prerequisite — once the error handling architecture
exists, injecting malformed UPDATEs and NOTIFICATIONs over real TCP becomes
the natural way to verify it. Before RFC 7606 there is less to test.

---

## General

### Testing strategy — overall picture (2026-06-11)

The project uses four complementary testing layers. The goal is near-complete coverage;
some paths (terminal I/O, async streams, long-running timers) are tested through
integration rather than direct unit tests.

**Layer 1 — Unit tests** (pure functions, no I/O)
- `pathvector-types`: all type constructors, well-known constants, encode/decode round-trips.
- `pathvector-policy`: term evaluation, action application, all condition variants.
- `pathvector-rib`: `select_best` steps, `LocRib`/`AdjRibIn`/`AdjRibOut` mutation and consistency.
- `pathvectord::propagate_prefix`, `flush_updates`, `prepare_outbound`: all pure functions;
  testable with `StubRibView` (no `DaemonState` construction needed).
- `pathvector/src/dashboard`: `apply_peer_event` / `apply_route_event` — pure state-mutation;
  15 tests cover all event variants, error paths, and upsert semantics.

**Layer 2 — Property tests (proptests)**
- `pathvector-session`: codec round-trips for all BGP message types + capabilities.
- `pathvector-rib`: all 8 best-path decision-step invariants + structural RIB invariants.
- `pathvector-policy`: determinism + first-match-wins + 8 action invariants.
- _Gap_: `pathvectord` event-loop transitions don't have proptests yet. The `DaemonState`
  update/withdraw/originate methods are good candidates — adding property tests for the
  consistency invariant "every prefix in `AdjRibOut` is also in `LocRib`" would close this.

**Layer 3 — Integration / session tests**
- `pathvectord` unit tests (200+ in `main.rs`) drive the full `run_event_loop` via
  `MockSessionHandle` — verify FSM transitions, import/export policy, route propagation,
  origination, stall detection, BLACKHOLE handling, RFC 8212 defaults, and more.
- `pathvector-session` FSM proptests drive the session state machine with random event
  sequences, verifying no unexpected state is reachable.

**Layer 4 — End-to-end tests** (Docker, GoBGP)
- 35 tests across `e2e/tests/` covering: session establishment, route import/export,
  policy enforcement, origination, withdrawal, and multi-peer topologies.
- Tests use the full stack: `pathvectord` binary inside a container, GoBGP as the peer,
  `PathvectorClient` gRPC API for assertions.
- BIRD and FRR interoperability both done (2026-06-14). See Tier 3 items 7 and 8.

**Dependency inversion progress**

| Seam | Abstraction | Status |
|------|-------------|--------|
| Session transport | `SessionHandle` trait | ✅ `MockSessionHandle` in use |
| RIB best-route lookup | `RibView<A>` trait | ✅ Done (2026-06-11) |
| Full RIB store | `impl RibStore` | ❌ Deferred |
| Policy engine | `impl PolicyEngine` | ❌ Deferred |
| Streaming mock clients | `MockDaemonClient::peer/route_events` queues | ✅ Done (2026-06-11) |

**Known coverage gaps**

- `run_dashboard` terminal I/O path — not unit-testable; covered by the stream unit tests
  plus e2e visual inspection.
- `pathvectord` clock/timer behaviour (hold timer, connect-retry timer) — no `Clock` trait
  injection yet. Deferred until MRAI or dampening requires it.
- `pathvector-client` conversion layer fuzz target — deferred until proto types stabilise.

---

### Property testing and fuzz coverage (ordered)

Proptests and fuzzing serve different purposes and should be added in this order:

- **Proptests** prove structural invariants hold for all valid inputs — RFC conformance evidence.
- **Cargo fuzz** proves arbitrary byte input never panics or corrupts state — panic-safety story.

**Phase 6 — `pathvector-client` conversion layer fuzz target** (deferred)
The `pathvector-client` crate is a trust boundary — it parses responses from a daemon over
the network, and the daemon could be buggy or compromised. The conversion layer
(`src/convert.rs`) does address parsing from `String`, enum coercion with unknown-value
handling, and fixed-width extended-community byte slicing (8 bytes each). A fuzz target that
generates arbitrary proto-encoded `Route` / `PeerState` bytes and drives the full `TryFrom`
chain would catch panics in these paths. Unlike the codec fuzz targets (which test
adversarial *peer* input), this tests adversarial *daemon* responses — a different attack
surface. Add to `fuzz/fuzz_targets/client_convert.rs` once the proto message structures
stabilise (adding streaming RPCs will change the generated types).

---

## pathvector-rib

### Best-path selection — missing decision steps

RFC 4271 §9.1 defines a 10-step decision process. The current implementation
covers steps 2, 3/7, 4, 5, 6, 9, and 10. The two remaining steps require
external information not available at the RIB layer:

| Step | Criterion | Status |
|---|---|---|
| 1 | Prefer routes with a reachable next-hop | ⚠️ `NextHopOracle` trait exists; `AlwaysReachable` stub — needs FIB integration |
| 8 | Prefer route with lowest IGP metric to next-hop | ⚠️ `NextHopOracle::igp_metric` wired into decision process; stub returns `None` — needs FIB |

Steps 3 (locally-originated routes prefer over learned) and 7 (eBGP over iBGP) are
**done** — both are handled by the `PeerType` ordering (`Local > External > Internal`)
in `select_best`. When a route is originated via `originate_route`, it is tagged
`PeerType::Local` in `grpc.rs` and wins at step 3/7 against any peer-learned route.

### Trait-based RIB and policy seams

**Remaining seams** — `pathvectord` still depends concretely on `AdjRibIn`, `AdjRibOut`,
and `Policy<Route<Ipv4Addr>>` at the `DaemonState` level. Full inversion (allowing
third-party RIB or policy implementations) would require `impl RibStore` + `impl PolicyEngine`
traits in a new thin `pathvector-core` crate, or accepting upward dependency in
`pathvector-rib`/`pathvector-policy`. Deferred until the embedding use-case becomes concrete.

### Multi-path (ECMP)

Best-path selection currently picks exactly one winner. BGP ECMP
(equal-cost multi-path) allows multiple routes to be installed simultaneously
when their path cost is equal up to and including step 8. Requires a
`MultiPath` variant in the best-route representation and configuration to
enable (`maximum-paths` knob).

### Route reflector — known gaps

1. **ORIGINATOR_ID loop detection** — RFC 4456 §8 SHOULD: if received `ORIGINATOR_ID` equals
   our own `bgp_id`, discard the UPDATE. Currently only `CLUSTER_LIST` loop detection is
   implemented. Low priority (prevents mis-configured self-reflection).

2. **CLUSTER_LIST loop detection scope** — The inbound loop check fires only for routes
   from RR clients. Routes from non-client iBGP peers that carry a `CLUSTER_LIST` (i.e.,
   already reflected by another RR) should also be loop-checked before entering our Loc-RIB.

3. **eBGP routes not getting reflection attributes** — When an eBGP-learned route is
   reflected to iBGP clients, it does not receive `ORIGINATOR_ID` / `CLUSTER_LIST`. RFC 4456
   §8 requires these on all reflected routes, including those learned from eBGP peers.

4. **IPv6 AdjRibOut not RR-aware** — `on_established` and `on_terminated` reset IPv6
   `AdjRibOut` without calling `new_reflecting`. `propagate_to_all_peers_v6` has no
   RR split-horizon logic. IPv6 reflection requires the same changes applied to IPv4.

### FIB integration (Netlink / kernel route installation) — remaining gaps

**Remaining gap:**

**2. `DaemonOracle` not wired into best-path selection** (`pathvector-rib`,
`pathvectord`) — `LocRib::recompute_best` calls `select_best` (→ `AlwaysReachable`)
rather than `select_best_with_oracle`. RFC 4271 §9.1 steps 1 and 8 remain dead
code at runtime. Fix: add `oracle: &dyn NextHopOracle` to `LocRib` construction
or to `recompute_best`; thread `DaemonOracle` in from `run_with`. This is the
architecturally deepest remaining gap.

**Testing gaps:**

- E2e test (Gap 8): after session with GoBGP establishes and a prefix is learned,
  assert `ip route show table 254` inside the container contains the prefix;
  on teardown assert it is removed. Also covers stale-route cleanup (Gap 4) end-to-end.

### Maximum prefix limits

No per-peer `max_prefixes` guard. A peer that sends more prefixes than expected
should trigger a CEASE NOTIFICATION (RFC 4486 subcode 1 — Maximum Number of Prefixes
Reached) and optionally restart after a configurable idle-hold timer.

Config shape:
```toml
[[peers]]
address     = "10.0.0.1"
remote_as   = 65001
max_prefixes = 100          # optional; no limit if absent
max_prefixes_restart = 300  # idle-hold seconds before reconnect; 0 = no restart
```

Implementation: count `AdjRibIn` entries per peer on each `INSERT` event in
`handle_update`; if the count exceeds the limit, send `CEASE/MaximumPrefixes` and
move the FSM to Idle. Cover with an e2e test using a GoBGP peer configured to
announce more prefixes than the limit.

### Configurable MED behaviour

The current implementation compares MED **globally across all peers**, which is
equivalent to `always-compare-med`. RFC 4271 §9.1.2.2 requires MED to be compared
only between routes from the same neighboring AS; the current behavior can produce
suboptimal selection when routes from different ASes have MED set. Step 6 is
therefore marked ⚠️ in `pathvector-rib/RFC.md`.

Real implementations offer:
- `always-compare-med` — current behavior (violates RFC default, but widely offered)
- `deterministic-med` — group routes by originating AS before comparing MED,
  ensuring the same best path is chosen regardless of route arrival order
- Configurable missing-MED treatment (`0`, `u32::MAX`, or policy-set)

---

## pathvector-session

### Remaining

- BGP-SEC (RFC 8205) — cryptographic path validation; further out, but worth noting alongside MD5 as the broader authentication story
- Graceful Restart FSM behaviour (RFC 4724) — capability is parsed and forwarded in `SessionInfo`, but the FSM does not yet act on it (hold forwarding state, stale route timer)
- NOTIFICATION support for Graceful Restart (RFC 8538) — allows sending CEASE NOTIFICATION during the GR window without tearing down the restart; extends RFC 4724; depends on Graceful Restart FSM
- Enhanced Route Refresh (RFC 7313) — adds `ORF_BEGIN` / `ORF_END` markers so the receiver knows when a full re-advertisement is complete; extends RFC 2918; currently codec-only
- Extended admin shutdown communication (RFC 9003) — extends CEASE NOTIFICATION (RFC 4486) with a UTF-8 freetext reason string (max 128 bytes); small addition on top of existing CEASE infrastructure
- BGP Role attribute / route leak prevention (RFC 9234) — `ROLE` OPEN capability and `ONLY_TO_CUSTOMER` community; automatic leak detection at the session layer; requires role config per peer (`provider`, `customer`, `rs`, `rs-client`, `peer`)
- Per-peer hold timer and keepalive interval — currently held in `SessionConfig` at a fixed value; should be configurable per peer in `PeerConfig` with a global fallback in `[daemon]`
- Outbound ROUTE-REFRESH trigger — send a `ROUTE-REFRESH` message to a peer to request their full table re-advertisement (protocol-level inbound soft reset); currently soft reset is API-driven only; requires RFC 2918 capability negotiation guard (already present)
- IPv6 peer MD5 authentication — currently `Unsupported` in `pathvector-sys`; would need a separate ABI path (`sockaddr_in6` in the `TcpMd5Sig` struct)

---

## pathvector-bmp

Not yet started. Key work items:

- BMP receiver (RFC 7854): Route Monitoring, Stats Reports, Peer Up/Down messages
- Route Monitoring NLRI → `Route<A>` → `AdjRibIn` pipeline
- Per-peer RIB view reconstruction from BMP stream

---

## pathvectord

### Remaining

- **Dynamic peer reconfiguration (runtime config)** — the daemon reads its
  configuration once at startup; adding, removing, or modifying a peer requires
  a full restart. Real operators need to add/remove peers, change import/export
  policy, and adjust timers without a restart (and without a BGP session reset
  to unaffected peers). This is the primary operational gap separating pathvector
  from a production-grade replacement for GoBGP or BIRD. Approaches to consider:
  - **gRPC-driven live config**: extend `DaemonService` with `AddPeer` / `RemovePeer`
    / `UpdatePeer` RPCs; `DaemonState` grows a mutable peer table; new sessions are
    spawned on-the-fly, existing sessions receive a `Stop` if the peer is removed.
  - **Config-file watch + partial reload**: inotify/kqueue watcher re-reads
    `pathvectord.toml` on change and diffs against running state; only affected
    sessions are touched.
  Either approach requires the session spawn path to be callable at runtime, not
  just during `build_daemon`. The gRPC approach is simpler to implement correctly
  first; config-file reload can wrap it.

- **`on_terminated` missing RouteEvents** — when a peer session drops,
  `loc_rib.withdraw_peer` removes the peer's routes but no `RouteEvent`s are
  emitted to the broadcast channel. The dashboard therefore shows stale routes
  after a peer disconnects until the next reconnect/snapshot. Fix:
  call `emit_route_events(&prev_prefixes)` after `withdraw_peer` (routes that
  lost their only candidate emit Withdrawn; routes promoted to another peer's
  candidate emit Announced with the new best). Tests: assert that
  `route_tx` receives Withdrawn events for each route removed on termination.

- **IPv6 BGP transport** — TCP sessions over IPv6 (bind listener on `[::]:179`,
  dial peers at IPv6 addresses). Distinct from IPv6 NLRI (MP_REACH_NLRI over IPv4
  sessions), which already works. Requires `IpAddr::V6` support throughout
  `PeerConfig`, `DaemonState`, and the TCP listener. MD5 auth for IPv6 peers is
  also currently `Unsupported` in `pathvector-sys` and would need a separate ABI
  path (`sockaddr_in6` in the `TcpMd5Sig` struct).

- **Dynamic neighbors** — accept BGP sessions from peers not explicitly configured,
  filtered by a source prefix range (e.g. `dynamic_peer_prefix = "10.0.0.0/24"`).
  Common at IXPs where the peer list changes without operator intervention. Requires
  the TCP listener to look up the peer by source IP or fall back to a dynamic
  neighbor template rather than failing with "unknown peer".

- **Peer groups** — a named config template applied to multiple peers; changing one
  field on the group propagates to all members without restarting unaffected sessions.
  Maps cleanly to a `[[peer_groups]]` TOML table and a `peer_group: Option<String>`
  field on `PeerConfig`.

- **Next-hop self** — force `NEXT_HOP` to the local router's address on iBGP
  re-advertisements. Essential when a route reflector sits between iBGP clients that
  cannot reach the original eBGP next-hop directly. Configurable per peer:
  `next_hop_self = true` in `PeerConfig`; applied in `prepare_outbound`.

- **AS path regex in policy** — match routes by AS path pattern
  (`^65001 ` for routes originated by AS 65001, `_65002_` for transit through AS 65002).
  Requires a regex condition in `pathvector-policy`; the `regex` crate is the natural
  choice. Most production policy engines expose this as a first-class condition.

- **RPKI / Route Origin Validation (RFC 6811)** — connect to an RTR validator
  (RFC 6810 / RFC 8210), receive ROA payloads, mark routes as Valid / Invalid /
  NotFound, and optionally filter Invalid routes in the import policy. Significant
  security feature; GoBGP, BIRD, and FRR all support it. Likely warrants a new
  `pathvector-rpki` crate owning the RTR client and validity cache, with a policy
  condition (`RoaValidityCondition`) consuming it.

- **IPv6 import policy per-AFI config** — currently IPv6 import policy is accept-all;
  per-AFI policy config (per-peer `import_default_v6`) is deferred.

---

## pathvector-client

### Remaining

- `serde` feature: `Serialize`/`Deserialize` derives are gated but not yet
  implemented on the domain types (blocked on deciding JSON schema conventions)
- Policy introspection RPC (`ListTerms`, `EvalRoute`) — blocked on
  `reapply_import_policy` being wired to export propagation in `pathvectord`

---

## Cross-cutting

### Design patterns / dependency-inversion improvements

Three targeted changes that improve testability or robustness without over-engineering.
Priority order matches the payoff-to-cost ratio.

1. **`RibSnapshot` split** — primarily a performance fix (see Performance item below),
   but also decouples gRPC reads from the event loop entirely.

2. **`Clock` trait for timer injection** (`pathvector-session`) — the `ConnectRetry` and
   `HoldTimer` timers are currently wired to `tokio::time` directly. A two-impl trait
   (`RealClock` / `MockClock`) would make timer-sensitive tests deterministic without
   relying on `tokio::time::pause()` (global state). Low urgency now; becomes important
   before adding route dampening (RFC 2439) or MRAI (RFC 4271 §9.2.1.1), both of which
   have complex timing logic that is difficult to test reliably with real timers.

   ```rust
   pub trait Clock: Send + Sync + 'static {
       fn now(&self) -> Instant;
       fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send;
   }
   ```

3. **`RibView` trait for `propagate_prefix`** (`pathvectord`) — already done for IPv4;
   ensure IPv6 path uses the same abstraction. Useful before best-path selection grows
   more complex (ECMP, route reflector client preference, etc.).

### Internal documentation on hard algorithms

The implementation has good API-level doc comments but the non-obvious logic
lacks prose explanation. A new contributor should not need to reconstruct the
RFC in their head to understand the code. Priority targets:

- **Best-path selection** (`pathvector-rib/src/best_path.rs`) — annotate each
  step with the RFC 4271 §9.1 section it implements and why the tie-breaking
  order is what it is
- **RIB eviction on `Terminated`** (`pathvectord/src/main.rs`, `on_terminated`)
  — explain the snapshot-before-withdraw pattern and why order matters
- **FSM state transitions** (`pathvector-session/src/fsm/`) — a table or
  diagram mapping each `(State, Input) → (State, Vec<Output>)` transition,
  with the RFC §8 reference for each arc

### Async cancellation safety audit

The forwarding tasks and event loop are correct under normal shutdown but have
not been audited for cancellation safety — specifically, what happens when a
future is dropped while awaiting `mpsc::Sender::send` or `recv`. Tokio's
channel operations are cancel-safe but any `select!` branch that performs
multi-step work (read + send) can lose progress if cancelled between steps.
Audit every `select!` site and every task spawn; document which futures are
cancel-safe and add `#[doc(cancel_safe)]` or inline comments where it matters.

### Structured error types

The current error story is a mix of `String`, ad-hoc enums, and `tonic::Status`
messages. A systematic pass should:

- Define typed error variants for the daemon event loop (`DaemonError`) so
  callers can match on "peer not found" vs "channel closed" vs "policy error"
  rather than inspecting strings
- Ensure every `tonic::Status` returned from a gRPC handler carries a
  meaningful `code` (not just `Internal`) and includes the original error in
  its message
- Verify `ConvertError` in `pathvector-client` covers all failure modes in the
  `TryFrom` impls with no hidden `unwrap()`

This partially overlaps with the Result/Option audit below but focuses on the
*shape* of errors at API boundaries rather than just their presence.

### Logging audit

The current `tracing` usage grew organically and needs a systematic review:

1. **Structured fields** — every log site should include typed fields rather than string
   interpolation. The convention should be `peer_addr = %addr` (Display) and
   `prefix = %prefix` consistently across all crates.
2. **Per-session spans** — each session task should be instrumented with a `tracing::span!`
   carrying `peer_addr` and `local_as` so that log output can be filtered per-peer without
   grepping. Currently logs from concurrent sessions are interleaved without a key.
3. **Level discipline** — establish and enforce:
   - `ERROR`: logic invariants violated (should never happen); always actionable
   - `WARN`: expected-but-bad external input (malformed message, peer misbehaviour)
   - `INFO`: operator-relevant lifecycle events (session established/terminated, route count changes)
   - `DEBUG`: per-message events useful for tracing protocol state
   - `TRACE`: raw byte-level detail; acceptable performance cost only in debug builds
4. **Hot paths** — the UPDATE processing path (`handle_update` → `LocRib::insert` →
   `propagate_prefix`) runs for every route change. Verify no `INFO`-or-above log sites
   sit inside the inner loop without rate-limiting.

### Result/Option return type audit

Any function that can fail should say so in its return type. Conduct a systematic pass:

1. **`expect()` / `unwrap()` survivors** — grep the entire workspace for `expect(` and
   `unwrap()` outside of `#[cfg(test)]` blocks; each one is either a legitimate invariant
   (document why it cannot fail) or should be replaced with a `Result` return and `?`.
2. **`()` returns that can fail silently** — functions returning `()` that perform I/O or
   parse input should return `Result<(), E>` and let the caller decide how to handle failure.
   The gRPC handler functions are the highest-risk area here.
3. **gRPC error propagation** — verify that every `tonic::Status` returned from a handler
   carries a meaningful `code` and `message`. An internal conversion error that maps to
   `Status::internal("unknown error")` is opaque to the caller; it should include the
   original error in the message.
4. **`ConvertError` completeness** — the `pathvector-client` conversion layer has explicit
   error variants. Verify no `unwrap()` or `expect()` hides inside any `TryFrom` impl.

- Integration test isolation — `tests/transport.rs` binds real loopback TCP sockets; these tests are excellent for correctness but will be slow and port-conflict-prone on shared CI runners; consider a `#[cfg(not(ci))]` guard or dedicated test binary with a randomised port range

### Performance

#### Known architectural concerns

These are structural decisions in the current implementation worth measuring before
deciding whether to address them. All are acceptable at small peer counts and RIB
sizes; they become bottlenecks at internet scale (tens of peers, ~950k IPv4 prefixes).

1. **Single event loop for all peers** — all peer sessions funnel into one `mpsc` channel;
   `DaemonState` processes events sequentially under a write lock. A large UPDATE from one
   peer (e.g., a full-table session establishment) blocks event processing for every other
   peer for the duration, creating hold-timer pressure at high peer counts. Sharding
   `DaemonState` by address family or introducing a per-peer processing pipeline would fix
   this, but requires significant ownership rework.

2. **No NLRI batching in outbound UPDATEs** — each affected prefix generates its own
   `UpdateMessage` and wire frame. RFC 4271 allows packing multiple NLRIs with identical
   path attributes into a single UPDATE. Batching reduces TCP segment count and framing
   overhead, which matters most during full-table dumps to newly established peers.

3. **Full-table dump on peer establishment holds the write lock** — `on_established`
   iterates the entire `LocRib` and calls `propagate_prefix` for every best route before
   releasing the write lock. At ~950k routes this is a multi-millisecond stall that blocks
   both the BGP event loop and all concurrent gRPC reads. Fix: generate the dump
   asynchronously, releasing the lock between batches.

4. **CoW under long-lived gRPC streams** — `Arc::make_mut` is zero-cost when refcount == 1
   (the common case). The risk is a future long-lived streaming handler retaining a snapshot
   Arc across yield points — that would make every UPDATE during the stream's lifetime a
   full RIB clone. Ensure streaming handlers never hold a snapshot `Arc` across `await`
   points. Audit any new streaming RPC before merging.

#### Per-crate criterion benchmarks

Each crate should have a `benches/` directory with criterion benchmarks. The goal is
a stable baseline on M2 Max hardware that can detect regressions as the implementation
evolves. Suggested targets:

| Crate | Benchmark | What to measure |
|---|---|---|
| `pathvector-types` | `as_path_prepend` | Prepend one AS to paths of length 0, 10, 100 |
| `pathvector-types` | `community_match` | Match a community against a set of 1, 10, 100 communities |
| `pathvector-policy` | `policy_evaluate` | Evaluate a policy of 1, 10, 50 terms against a single route |
| `pathvector-rib` | `loc_rib_insert` | Insert 100 / 1k / 10k routes from a single peer |
| `pathvector-rib` | `best_path_select` | Run `select_best` over 1, 4, 16, 64 candidates per prefix |
| `pathvector-rib` | `loc_rib_lpm` | `longest_match` over a 10k-route table (random IPv4 addrs) |
| `pathvector-rib` | `adj_rib_out_propagate` | `propagate_prefix` for 1k prefixes × 4 peers |
| `pathvector-session` | `codec_decode_update` | Decode an UPDATE carrying 1 / 100 / 1k NLRIs |
| `pathvector-session` | `codec_encode_update` | Encode the same UPDATE payloads |
| `pathvector-session` | `codec_roundtrip` | End-to-end encode → decode for all five message types |

All benchmarks should be reported with the three-size pattern (small / medium / large)
and a Takeaway column noting whether cost scales linearly, is O(log n), or is flat.
Hardware citation: Apple M2 Max, 96 GB RAM.

Add to `Justfile`:

```sh
bench:
    cargo bench --workspace
```

Once the baseline is established, wire benchmark regression detection into CI:
store the criterion output (JSON) as a CI artifact and fail the build if any
benchmark regresses by more than a configurable threshold (e.g. 10%). The
[`critcmp`](https://github.com/BurntSushi/critcmp) tool compares criterion
baselines and is straightforward to integrate into a GitHub Actions step.

#### System-level benchmarks against GoBGP and BIRD

Measuring the end-to-end convergence time and memory footprint of a real BGP speaker
under a realistic internet-scale prefix load requires a traffic generator.
**[ExaBGP](https://github.com/Exa-Networks/exabgp)** is the standard tool: it is a
Python BGP implementation that can replay MRT dumps as a BGP UPDATE stream, acting as
a fully conformant peer. MRT dump files from [RouteViews](http://www.routeviews.org/)
or [RIPE RIS](https://ris.ripe.net/dumps/) provide real internet routing tables
(~950k IPv4 prefixes as of 2026).

**Proposed benchmark scenario:**

1. Stand up ExaBGP (or a dedicated `exabgp` Docker container) configured to replay a
   full RouteViews MRT dump toward a single DUT (device under test).
2. Measure from the moment BGP `Established` is reached:
   - **Convergence time** — seconds from first UPDATE to RIB stable (no new best-path
     changes for 5 consecutive seconds)
   - **Peak RSS** — resident set size at the end of the full-table load
   - **Steady-state CPU** — CPU% after convergence with periodic keepalives only
   - **Hold-timer health** — did any KEEPALIVE interval slip during the flood?
3. Run the same scenario against GoBGP 4.x and BIRD 2.x on the same hardware with
   equivalent configuration (one eBGP peer, accept-all import policy).

**Docker composition** — the same testcontainers architecture used in the e2e suite
applies here. A `bench/` crate (or a standalone binary) could:
- Start an `exabgp` container serving the MRT dump
- Start the DUT container (pathvectord / gobgpd / bird)
- Poll via gRPC (pathvectord) or CLI (gobgp/birdc) until RIB prefix count stabilises
- Record wall-clock time, RSS (`docker stats --no-stream`), CPU

**Prerequisites before this is actionable:**
- NLRI batching (concern #2 above) should be addressed first so outbound performance
  is not artificially penalised
- The full-table dump lock-hold (concern #3) should be measured separately from the
  inbound convergence benchmark
- A RouteViews MRT dump needs to be converted to ExaBGP's `announce` format (the
  `exabgp-mrt` tool does this); the converted file should be committed to `bench/fixtures/`
  (or downloaded by the benchmark harness to avoid repo bloat)

#### e2e / fault injection / chaos and backpressure tests

- **Fault injection / chaos tests** — inject TCP resets mid-session, corrupt
  bytes at the framing layer, and drop packets during the OPEN exchange; verify
  the FSM recovers cleanly rather than wedging. Prerequisite: RFC 7606 error
  handling so there is a defined response to malformed input.
- **Backpressure / sustained churn tests** — verify the channel-full stall
  detection and recovery under sustained route churn, not just a single crafted
  test case. Candidate scenario: ExaBGP replaying a partial MRT dump at high
  rate while a second peer's UPDATE channel is artificially constrained.

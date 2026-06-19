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
- `pathvectord/src/daemon.rs` (96.5%, ~194 missed lines) — async event-loop branches
  (session events, peer state transitions, route update handlers) require a mock session
  harness or lightweight integration scaffolding to drive the event loop without real TCP.
- `pathvector-sys/src/tcp.rs` (94.9%) — missed lines likely require real socket setup or
  Linux-only TCP MD5 paths; investigate whether mock sockets or platform-gated tests can close the gap.
- No e2e test for AS_TRANS wire encoding against a real 2-byte-only peer (GoBGP `--as2` mode) — unit tests exist but no interop verification.
- No IPv6 route receive/withdraw tests for BIRD and FRR peers — requires IPv6 variants of `write_bird_config` / `write_frr_config`, new `BirdHarness::new_v6()` / `FrrHarness::new_v6()` constructors, and `address-family ipv6` blocks in each speaker's config.
- `pathvector-session/src/transport/mod.rs` (96.0%) — `SessionCommand::Notification` branch
  (~line 411) and TCP send failure path (~line 479) require a real or mock transport pair
  to drive the async session loop.

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

### Best-path selection — decision steps

All 10 RFC 4271 §9.1 decision steps are implemented. Steps 1 and 8 require live
FIB data and are active only on Linux where `KernelFib` populates the snapshot via
rtnetlink. On macOS (development) the daemon falls back to `AlwaysReachable`.

| Step | Criterion | Status |
|---|---|---|
| 1 | Prefer routes with a reachable next-hop | ✅ `DaemonOracle` + `KernelFib` on Linux; `AlwaysReachable` on macOS |
| 2 | Highest LOCAL_PREF | ✅ |
| 3/7 | Local origin > eBGP > iBGP | ✅ `PeerType` ordering |
| 4 | Shortest AS_PATH | ✅ |
| 5 | Lowest ORIGIN | ✅ |
| 6 | Lowest MED (same neighboring AS only) | ✅ Group-based selection, insertion-order stable |
| 8 | Lowest IGP metric to next-hop | ✅ `KernelOracle::igp_metric` on Linux; skipped on macOS |
| 9 | Oldest eBGP route | ✅ |
| 10 | Lowest peer router-id | ✅ |

Tested via `test_on_fib_change_withdraws_when_next_hop_goes_down`,
`test_on_fib_change_reannounces_when_next_hop_recovers`, and
`test_on_fib_change_noop_when_nothing_changes` in `daemon.rs`.

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

### Route reflector — known sub-optimalities

~~Items 1, 3, 4, 5, 6 resolved 2026-06-19. Full RFC 4456 §8 compliance implemented and audited.~~

~~**A. `best_peer()` called twice per prefix per peer in the propagation loop** — **Resolved 2026-06-19**: `best_peer` is now computed once at the top of `propagate_prefix` and `propagate_prefix_v6`, eliminating the second internal call. The split-horizon check in the daemon closures still calls `best_peer` for RR topology filtering, but the function-internal redundant call is gone.~~

~~**C. No e2e test for route reflection** — **Resolved 2026-06-19**: `RrHarness` added to `pathvector-e2e/src/lib.rs` (three-container: GoBGP-client, pathvectord RR, GoBGP-non-client, all AS 65002 iBGP). Three tests in `pathvector-e2e/tests/route_reflector.rs`: `rr_client_route_reflected_to_non_client`, `rr_non_client_route_reflected_to_client`, `rr_client_route_visible_in_pathvectord_rib`.~~

~~**D. `peer_bgp_ids` reconfiguration race window** — **Resolved 2026-06-19**: `peer_bgp_id: Ipv4Addr` is now a parameter of `on_established` and inserted atomically with `peer_types`, eliminating the split at the call site in `run_event_loop`. The fallback `unwrap_or(peer_ip)` in ORIGINATOR_ID injection cannot materialize because `peer_bgp_ids` is always populated before the peer appears in `peer_types`.~~

**E. Multi-tier RR topology not tested** — existing e2e tests cover a single-reflector
topology (one RR, one client, one non-client). A two-tier or cascaded-RR topology
(client → RR1 → RR2 → non-client) exercises different code paths: CLUSTER_LIST must
accumulate correctly across hops, ORIGINATOR_ID must be preserved (not overwritten) at
RR2, and loop detection must fire if the route circles back. None of this is tested at
the wire level today. The unit tests cover the direct attribute-injection cases but not
the multi-hop invariants. Requires a four-container harness with two pathvectord
instances or one pathvectord + one GoBGP-as-RR.

### FIB integration (Netlink / kernel route installation) — remaining gaps

**Remaining gaps:**

**Recursive next-hop resolution** (`pathvector-sys`, `pathvector-rib`) — allow BGP
routes to serve as IGP paths when resolving other BGP next-hops (RFC 4271 §5.1.3 note;
used in MPLS/VPN and some overlay topologies). Requires a second snapshot layer or a
recursive lookup pass in `KernelOracle::is_reachable` that consults the BGP Loc-RIB,
plus loop-detection to prevent infinite recursion. Explicitly not implemented; the
current design excludes BGP routes from `FibSnapshot` for correctness (no feedback loop,
semantic separation of IGP and BGP RIBs).

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

Step 6 now correctly applies MED only between routes from the same neighboring AS
(`AsPath::neighboring_as()` comparison in `select_best`). Routes from different ASes
skip the MED step entirely, falling through to step 3/7 (peer type) and beyond.

What remains as optional future work:
- `always-compare-med` knob — some operators want cross-AS MED comparison; JUNOS/IOS
  both offer this as an explicit opt-in
- Configurable missing-MED treatment (`0`, `u32::MAX`, or policy-set; current: `0`)
- `deterministic-med` — ensures stable selection regardless of route arrival order
  when multiple routes from the same AS arrive at different times

---

## pathvector-session

### Remaining

- BGP-SEC (RFC 8205) — cryptographic path validation; further out, but worth noting alongside MD5 as the broader authentication story
- Graceful Restart FSM behaviour (RFC 4724) — capability is parsed and forwarded in `SessionInfo`, but the FSM does not yet act on it (hold forwarding state, stale route timer)
- NOTIFICATION support for Graceful Restart (RFC 8538) — allows sending CEASE NOTIFICATION during the GR window without tearing down the restart; extends RFC 4724; depends on Graceful Restart FSM
- BGP Role attribute / route leak prevention (RFC 9234) — `ROLE` OPEN capability and `ONLY_TO_CUSTOMER` community; automatic leak detection at the session layer; requires role config per peer (`provider`, `customer`, `rs`, `rs-client`, `peer`)
- IPv6 peer MD5 authentication — currently `Unsupported` in `pathvector-sys`; would need a separate ABI path (`sockaddr_in6` in the `TcpMd5Sig` struct)

~~**Enhanced Route Refresh codec (RFC 7313)** — adds `BeginRefresh` / `EndRefresh` subtypes so the receiver knows when a full re-advertisement is complete; extends RFC 2918.~~
~~**Resolved 2026-06-18**: `RouteRefreshSubtype` enum added to `pathvector-session`. The previously reserved byte in the ROUTE-REFRESH wire format is now decoded as `Refresh` (0), `BeginRefresh` (1), or `EndRefresh` (2). Encode/decode updated; 4 new codec tests added.~~

~~**Extended admin shutdown communication (RFC 9003)** — extends CEASE NOTIFICATION (RFC 4486) with a UTF-8 freetext reason string (max 128 bytes).~~
~~**Resolved 2026-06-18**: `encode_shutdown_message` / `decode_shutdown_message` added to `pathvector-session::message::notification`. `pathvectord` reads `shutdown_message: Option<String>` from `PeerConfig`; `RemovePeer` sends `Cease/AdministrativeShutdown` with the encoded payload instead of a bare `Stop` command. 6 new unit tests.~~

~~**Per-peer hold timer** — configurable per peer in `PeerConfig` with a global fallback in `[daemon]`.~~
~~**Resolved 2026-06-18**: `PeerConfig.hold_time: Option<u16>` added. `build_daemon` and the `AddPeer` command processor both fall back to `DaemonConfig.hold_time` when the per-peer value is absent.~~

~~**Outbound ROUTE-REFRESH trigger** — send a `ROUTE-REFRESH` message to a peer to request their full table re-advertisement.~~
~~**Resolved 2026-06-18**: `SessionCommand::RouteRefresh(RouteRefreshMessage)` variant added. `SessionHandle::send_route_refresh` wired through `SpawnedSessionHandle`. `SoftReset` gRPC RPC added to `PeerService`; `PeerServiceImpl::soft_reset` sends a `RouteRefresh` command to the target peer's session actor.~~

---

## pathvector-bmp

Not yet started. Key work items:

- BMP receiver (RFC 7854): Route Monitoring, Stats Reports, Peer Up/Down messages
- Route Monitoring NLRI → `Route<A>` → `AdjRibIn` pipeline
- Per-peer RIB view reconstruction from BMP stream

---

## pathvectord

### Dynamic peer management — known gaps (2026-06-18)

Six gaps identified during a correctness audit of the `AddPeer`/`RemovePeer` feature.
Items 1, 4, 5, 6 are resolved (2026-06-18). Items 2 and 3 remain open.

~~**1. `add_peer` returns `OK` when the peer is mid-teardown (`pending_removal`)** —
**Resolved 2026-06-18**: `grpc.rs` `add_peer` handler now checks `pending_removal`
before sending the command and returns `FAILED_PRECONDITION` if removal is in flight.
The command processor also logs a warn! and drops the add if the race is lost.~~

~~**2. Dynamic peers don't survive daemon restart** —
**Resolved 2026-06-18**: `config::DynamicPeerStore` writes a TOML sidecar
(`dynamic_peers.toml`) next to the config file on every `add_peer`/`remove_peer`
using atomic write-then-rename. `main.rs` loads the sidecar at startup and merges
peers into the config before `run_with`. Static-config peers take precedence (no
duplication). Six unit tests cover sidecar round-trips; two `run_with_tests`
integration tests prove the restart-loading path.~~

**3. MD5 password on dynamically-added peers doesn't work for inbound connections**

The BGP listener socket is bound once at startup; TCP MD5SIG keys cannot be added to
an existing listening socket on Linux without rebinding. Dynamically-added peers with
`md5_password` only work for outbound connections (pathvectord dials them). If the
remote peer tries to initiate toward us, the listener rejects the TCP handshake because
no key is installed for that source address.

Fix (full): re-bind the listener socket when a new MD5 peer is added — requires moving
the listener into a task that can be restarted. Documented in `pathvectord/README.md`.

~~**4. `watch_peers` stream behavior after dynamic add/remove is unverified** —
**Resolved 2026-06-18**: Traced and fixed. `on_terminated` now suppresses its
`Changed(None)` broadcast during removal. The event loop captures `remote_as`/`local_as`
before state is erased, then broadcasts an explicit `Removed(Some(PeerState))` event
carrying correct identity fields. The stream handler forwards it directly. Dashboard
`apply_peer_event` handles `Removed` by calling `retain`. Unit tests added for all
`Removed` cases. E2e `DynamicPeerHarness` + `wait_for_peer_absent` helper added.~~

~~**5. Event loop stall on large-peer removal is unbounded and underdocumented** —
**Resolved 2026-06-18**: `on_terminated` now records `Instant::now()` before the
propagation loop and emits `tracing::warn!` if the loop exceeds 100 ms, including
peer address, prefix count, and elapsed milliseconds.~~

~~**6. No watchdog for `run_command_processor` task panics** —
**Resolved 2026-06-18**: `run()` now wraps the processor join handle in a second
`tokio::spawn` that logs `tracing::error!` if the task exits with a panic.~~

### API ergonomics

**Bare IP address as host route in gRPC prefix fields** — the gRPC API currently
requires explicit CIDR notation for all prefix fields (e.g. `192.0.2.1/32`). Submitting
a bare IP address (`192.0.2.1`) returns `invalid_argument: 'x' is not valid CIDR
notation`. Most BGP CLIs (BIRD, GoBGP, FRR) silently accept a bare IP and coerce it to
a `/32` (IPv4) or `/128` (IPv6) host route.

Open question: is strict CIDR the right contract for an API (explicit is less surprising
for programmatic callers) or should we match CLI convention for operator ergonomics?

If we do coerce: the fix is a small fallback in `parse_nlri` / `parse_nlri_v6` in
`pathvectord/src/grpc.rs` — try CIDR parse first, fall back to bare `IpAddr` + `/32` or
`/128`. The proto field comment and client docs would need to reflect the relaxed rule.

### Remaining

- **`ListRoutes` gRPC response hits 4 MB tonic limit at ~26k routes** — confirmed by stress test (2026-06-17). The default tonic `max_decoding_message_size` is 4 MB; a response with 100k routes (~150 bytes each) exceeds this. Cursor pagination already exists (`page_size`/`page_token`); callers MUST use it for large tables. Remaining gap: add a `CountRoutes` RPC so callers can check table size before deciding whether to paginate or use `WatchRoutes` for a streaming snapshot.

- **`UpdatePeer` RPC** — modify import/export policy or timers on an existing peer
  without a full session reset. Requires diffing old vs. new `PeerConfig` and only
  touching what changed: a policy update needs no session bounce; a hold-timer change
  requires a NOTIFICATION + reconnect to the affected peer only. Builds on the
  `DaemonCommand` + `run_command_processor` pattern introduced for `AddPeer`/`RemovePeer`.

- **Config-file watch + partial reload** — inotify/kqueue watcher re-reads
  `pathvectord.toml` on change, diffs against running state, and drives
  `AddPeer` / `RemovePeer` / `UpdatePeer` commands. Thin wrapper around the gRPC
  command path; `UpdatePeer` is the prerequisite.

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

~~**Next-hop self** — **Resolved 2026-06-19**: `next_hop_self: bool` added to `PeerConfig`; `RibSnapshot.next_hop_self_peers: HashSet<Ipv4Addr>` stores enabled peers; `prepare_outbound`/`prepare_outbound_v6` rewrite NEXT_HOP for iBGP peers with this flag set; all propagation paths (`propagate_to_all_peers`, `propagate_to_all_peers_v6`, `on_established`, `on_terminated`, `set_export_default`) pass `next_hop_self` per peer. Unit test `test_propagate_to_all_peers_next_hop_self_rewrites_ibgp_next_hop` added.~~

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

~~**`reapply_import_policy` has no IPv6 counterpart** — **Resolved 2026-06-19**: `reapply_import_policy_v6` added to `pathvectord/src/daemon.rs`; `set_import_default` now calls both the v4 and v6 variants so a policy reload applies to all address families without a session reset. Two unit tests added: `test_reapply_v6_accepts_previously_rejected_route`, `test_reapply_v6_rejects_previously_accepted_route`.~~

~~**`cluster_id` configuration guidance** — **Resolved 2026-06-19**: `DaemonConfig::cluster_id` doc comment expanded in `pathvectord/src/config.rs` with an explicit "multi-cluster deployments" warning: distinct `cluster_id` values are required per cluster, otherwise CLUSTER_LIST loop detection fires incorrectly across clusters.~~ Without explicit configuration, loop detection via CLUSTER_LIST will behave unexpectedly if clusters share a `cluster_id`. Document in `pathvectord/README.md` with an explicit "if you run multiple RR clusters, set distinct `cluster_id` values" callout alongside the `is_route_reflector` config example.

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

#### Memory — resolved by rib-memory-opt (2026-06-17)

Stress benchmark (release profile, Apple M2 Max, synthetic uniform routes):

| Table size | pathvectord RSS | GoBGP RSS | Ratio |
|---|---|---|---|
| 10k  | 11.8 MB  | 51.7 MB  | pathvector 4.4× less |
| 100k | 66.8 MB  | 133.2 MB | pathvector 2.0× less |
| 500k | 461.2 MB | 465.4 MB | ~equal |
| 900k | 515.2 MB | 792.4 MB | pathvector 35% less |

Per-route at 900k: **0.57 KB/route** (pathvectord) vs **0.88 KB/route** (GoBGP).

The RSS plateau between 500k–900k (+54 MB for 400k additional routes) confirms
that attribute interning / Arc-sharing is effective — real internet routes converge
onto a small set of shared attribute sets as the table grows.

No further memory audit planned unless profiling on a real multi-peer internet
table (not synthetic) reveals a regression.

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

~~`pathvector-rib` — **Resolved 2026-06-18**: Three bench targets shipped:
`select_best` (2/10/100 candidates), `loc_rib_insert` (10k/100k/500k prefixes),
`outbound_pipeline` (1/10/50 peers × minimal/dense route). Baseline on M2 Max:
`select_best/2` 158 ns, `select_best/100` 2.6 µs; `loc_rib_insert` flat at ~600 ns
across all RIB sizes; `outbound_pipeline/minimal/50` 6.8 µs,
`outbound_pipeline/dense/50` 13.7 µs.~~

Remaining crates to benchmark:

| Crate | Benchmark | What to measure |
|---|---|---|
| `pathvector-types` | `as_path_prepend` | Prepend one AS to paths of length 0, 10, 100 |
| `pathvector-types` | `community_match` | Match a community against a set of 1, 10, 100 communities |
| `pathvector-policy` | `policy_evaluate` | Evaluate a policy of 1, 10, 50 terms against a single route |
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

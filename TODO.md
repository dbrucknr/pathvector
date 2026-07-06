# TODO

Tracked items that are intentionally deferred — known gaps, planned features,
and protocol steps that require components not yet built. Each entry notes
which crate it belongs to and why it was deferred.

---

## Production readiness gaps (2026-06-24)

Items identified as blocking or materially impairing trustworthy production
operation of pathvectord as an internet-facing BGP speaker.

### Tier 1 — Blocks operating safely on the internet

**RPKI / Route Origin Validation (RFC 6810/6811/8210)** — shipped, both phases.
Phase 1 (RTR client + ROA cache) and Phase 2 (policy-layer filtering: reject
`Invalid`, accept `Valid`/`NotFound`, matching RFC 7115 / BIRD / FRR
convention, via `pathvector-policy`'s `RoaValidityCondition` wired into every
peer's import policy by `pathvectord`, gated by `[daemon.rpki].reject_invalid`
— default `true`) are both complete; see CHANGELOG.md. One non-blocking
optimization remains, tracked in the General section below:
`routemap::covering_matches()`.

**Route leak prevention (RFC 9234)** — shipped. BGP Role capability (code 9,
`provider`/`rs`/`rs_client`/`customer`/`peer` via `PeerConfig.role`), role-pair
correctness at OPEN (NOTIFICATION on mismatch), and the `ONLY_TO_CUSTOMER`
attribute's full ingress/egress leak-detection and attach/block semantics are
implemented across `pathvector-session`, `pathvector-rib`, `pathvector-policy`,
and `pathvectord`, with a real e2e proof over an actual BGP session (see
`pathvector-e2e/tests/role.rs` and the per-crate `RFC.md` files). OTC egress
enforcement now applies to both IPv4 and IPv6 routes (the IPv6 export-policy
gap this depended on was closed — see the General section below). One
non-blocking follow-up remains, tracked in the General section below: strict
mode (reject when only one side advertises Role).

---

### Tier 2 — Operability and reliability

**Operational telemetry / observability**

A Prometheus `/metrics` endpoint shipped 2026-07-01 (see CHANGELOG.md), covering
session state, uptime timestamps, per-peer prefix counts, and session termination
reasons. See `pathvectord/README.md` Observability section for the full metric
reference. Three real-world usage gaps closed 2026-07-05 (found via
BlockingArbiter-RS's Grafana dashboard, see CHANGELOG.md): a configured-but-never-
established peer now gets zeroed gauges at startup/`AddPeer` instead of no series at
all (`register_peer`); `pathvectord_bgp_updates_sent_total{peer}` now exists as the
outbound counterpart to `updates_received_total`; and the global
`pathvectord_bgp_loc_rib_prefixes{afi}` gauges are now pre-set to 0 at startup
instead of only appearing once the first peer establishes or flushes a route.
Three further gaps — FIB write-failure visibility, self-originated route count,
and import-policy-reject visibility — were closed 2026-07-06 (see CHANGELOG.md),
also found via a review of BlockingArbiter-RS's actual usage. Remaining
follow-ups from that work:

- **No export-side policy-rejection visibility.** The 2026-07-06 import-policy
  counter has no export-side counterpart — a route dropped by export policy
  (as opposed to withdrawn for some other reason) is silently absent from
  Adj-RIB-Out with no metric to distinguish the two. Blocked on the same
  wide-call-site problem already solved once for `updates_sent_total`
  (`outbound.rs`'s `propagate_prefix`/`propagate_prefix_v6`, ~13 call sites),
  plus `PrefixDecision`/`PrefixDecisionV6`'s 3 variants not yet distinguishing
  "policy rejected" from other withdraw causes (e.g. split-horizon).
- **No granular import-policy-reject reason label.**
  `pathvectord_bgp_import_policy_rejected_total{peer}` cannot currently carry a
  `reason` label (e.g. `rpki_invalid`, `otc_leak`) because
  `pathvector_policy::Decision` is a bare 3-variant enum with no information
  about which `Term`/`Condition` fired — would need a larger change to
  `pathvector-policy`'s evaluation API.
- **`fib_routes_installed` has no external reconciliation.** The gauge is purely
  incremental from `fib::process_batch`'s own success/failure outcomes; a
  silent kernel-side failure that never surfaces as an `Err` would drift the
  gauge with no self-correction. A periodic netlink route-table dump/diff pass
  would close this.

- **Series pruning on `RemovePeer`.** Metric series are labeled by peer IP and are
  zeroed but never removed when a peer is deconfigured. Fine for static peer sets;
  becomes unbounded growth for deployments that churn peers frequently via the
  dynamic-peer gRPC API. Fix: call a `remove_peer_series(peer_ip)` helper in
  `pathvectord/src/metrics.rs` from the `RemovePeer` handling arm in
  `daemon/mod.rs`, using the Prometheus recorder handle's descriptor-clear API
  (`metrics_exporter_prometheus::PrometheusHandle` does not currently expose a
  direct per-series clear — may require tracking the recorder handle in
  `DaemonState` and filtering the rendered text, or a version bump if a newer
  release adds this).
- **GR window active/expired events** — not yet emitted as metrics.
- **NOTIFICATION send/receive events with subcode** — not yet emitted as metrics.
- **Post-install task supervision.** `metrics_exporter_prometheus::install()` spawns
  the HTTP listener as a detached Tokio task; we hold no `JoinHandle` to it (the
  crate's `install()` API doesn't expose one). A bind failure at startup is caught
  and logged (see 2026-07-01 CHANGELOG entry), but if the listener task panics or
  errors *after* startup, it fails silently — no log, no restart, metrics just stop.
  The rest of the daemon is unaffected (Tokio isolates per-task panics; BGP sessions
  and gRPC run in separate tasks). Fix: switch from `PrometheusBuilder::install()` to
  `.build()`, which returns the exporter future directly — spawn it ourselves and log
  if the `JoinHandle` ever resolves.
- **BMP (RFC 7854)** — complementary to, not a replacement for, Prometheus metrics:
  BMP streams every raw UPDATE/RIB-in/RIB-out event to a monitoring station for
  route-level introspection and incident forensics, while Prometheus exposes
  aggregate health signals (session up/down, counts, rates) for dashboards and
  alerting. Both are useful; BMP is still not started (`pathvector-bmp` crate is a
  stub).

**Capability negotiation retry (RFC 5492)**
If a peer sends `Unsupported Capability` NOTIFICATION, pathvectord does not
retry the session without the offending capability. Real-world peers — especially
older vendor gear — do this during capability negotiation. A session that cannot
recover requires manual `remove_peer` / `add_peer` intervention. The FSM already
has the `UnsupportedCapability` NOTIFICATION subcode parsed; the fix is a retry
loop in the connect/open path that drops the flagged capability and redials.
See `pathvector-session/RFC.md` RFC 5492 deferred section.

**Route flap dampening (RFC 2439)**
A peer whose route oscillates rapidly (flap) causes repeated best-path
recomputes and UPDATE bursts to all other peers. Without dampening, a single
unstable peer can drive CPU to 100% and trigger hold-timer expiry on unrelated
sessions. RFC 2439 defines a penalty accumulation + half-life decay model that
suppresses flapping prefixes. Requires a per-(peer, NLRI) penalty counter and
a background decay timer — architecturally similar to the GR deadline timer
already in the event loop. `pathvector-rib` would own the penalty model;
`pathvectord` wires the timer branch.

**Lock contention risk in full-daemon policy re-evaluation (2026-07-02)**
`DaemonState::reevaluate_all_import_policies` (`pathvectord/src/daemon/policy.rs`)
holds `DaemonState`'s single write lock for the entire duration of a sweep over
*every* configured peer's Adj-RIB-In, re-running import policy on each stored
route. It's called automatically by the background task `install_rpki` spawns
(`daemon/mod.rs`), once per RPKI ROA cache change (see the reactive
re-evaluation work in CHANGELOG.md) — i.e. on a cadence the daemon doesn't
control, potentially every RTR incremental sync. For a deployment with many
peers and large tables, this could mean a multi-peer stall of route
processing / peer state transitions / gRPC reads each time the RPKI cache
updates, since nothing else can acquire the write lock until the full sweep
finishes.

This isn't a new *pattern* — `DaemonState::set_import_default` (same file)
already holds the lock across one peer's full Adj-RIB-In re-evaluation via the
same `reapply_import_policy`/`reapply_import_policy_v6` primitives, and
`set_export_default` holds it across a full Loc-RIB scan for one peer. Both
are fine as-is: they're triggered by an explicit, infrequent operator action
(a gRPC call), so the stall is bounded and expected. `reevaluate_all_import_policies`
is the first caller that (a) sweeps *every* peer in one lock hold and (b) fires
on an external, potentially frequent trigger instead of a deliberate one —
it's an amplification of an existing, previously-acceptable tradeoff into a
regime where it may no longer be.

Not fixed yet — flagged during self-review, not confirmed as an actual problem
in practice (RTR incremental syncs are typically infrequent, matching the
"stale-but-recent beats absent" philosophy already established for RPKI data).
If it does need addressing, candidate directions: (1) only re-evaluate peers
whose Adj-RIB-In actually contains a prefix covered by the changed ROA(s),
rather than every peer unconditionally; (2) drop and re-acquire the write lock
between peers instead of holding it for the whole sweep; (3) debounce rapid
successive `RtrHandle::subscribe()` notifications so a burst of incremental
syncs triggers one sweep, not one per notification.

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
- `pathvectord`: `rib_consistency_prop_tests::prop_adj_rib_out_always_subset_of_loc_rib`
  (`daemon/mod.rs`) drives random sequences of peer announce/withdraw (v4 + v6) and local
  originate/withdraw against a 3-peer `DaemonState` and asserts every prefix in each peer's
  `AdjRibOut` is present in `LocRib` after every operation — closed 2026-07-04.

**Layer 3 — Integration / session tests**
- `pathvectord` unit tests (460+ across `daemon.rs` and `outbound.rs`) drive the full `run_event_loop` via
  `MockSessionHandle` — verify FSM transitions, import/export policy, route propagation,
  origination, stall detection, BLACKHOLE handling, RFC 8212 defaults, and more.
- `pathvector-session` FSM proptests drive the session state machine with random event
  sequences, verifying no unexpected state is reachable.

**Layer 4 — End-to-end tests** (Docker, GoBGP)
- 74 tests across `e2e/tests/` covering: session establishment, route import/export,
  policy enforcement, origination, withdrawal, multi-peer topologies, route reflection,
  dynamic peers, and EOR markers.
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

**`routemap::covering_matches()`** (non-blocking optimization). `pathvector-rpki/src/table.rs`'s
`validate()` composes a `longest_match` short-circuit with a manual ancestor-prefix walk to
get RFC 6811's "all covering ROAs" semantics out of `routemap`'s single-winner LPM API. Since
`routemap` is our own crate, a native `covering_matches(prefix) -> impl Iterator<Item =
(IpPrefix<A>, &V)>` that walks the trie path once would be strictly better (one trie walk
instead of up to 33/129 `get()` calls) and would simplify `validate()` to a single loop. Not
required for correctness — see the "Future improvement" note in `table.rs`.

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

Items 1, 3, 4, 5, 6 (full RFC 4456 §8 compliance) resolved 2026-06-19 — see CHANGELOG.md.

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
- RFC 9234 strict mode — reject a session at OPEN when only one side advertises the
  Role capability. The RFC makes this optional and non-default (absence on either
  side is not a mismatch); implemented behavior matches the non-strict default.
  Add if an operator needs to enforce Role negotiation as a hard requirement.
- IPv6 peer MD5 authentication — currently `Unsupported` in `pathvector-sys`; would need a separate ABI path (`sockaddr_in6` in the `TcpMd5Sig` struct)

RFC 8538 (2026-06-24), RFC 4724 Phase 1+2 (2026-06-22), RFC 7313 (2026-06-18), RFC 9003
(2026-06-18), per-peer hold timer (2026-06-18), outbound ROUTE-REFRESH trigger
(2026-06-18), and RFC 9234 (2026-07-02) are all complete — see CHANGELOG.md.

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
Items 1, 2, 4, 5, 6 resolved 2026-06-18 — see CHANGELOG.md. Item 3 remains open.

**3. MD5 password on dynamically-added peers doesn't work for inbound connections**

The BGP listener socket is bound once at startup; TCP MD5SIG keys cannot be added to
an existing listening socket on Linux without rebinding. Dynamically-added peers with
`md5_password` only work for outbound connections (pathvectord dials them). If the
remote peer tries to initiate toward us, the listener rejects the TCP handshake because
no key is installed for that source address.

Fix (full): re-bind the listener socket when a new MD5 peer is added — requires moving
the listener into a task that can be restarted. Documented in `pathvectord/README.md`.

### watch_routes broadcast channel — guaranteed delivery

The `watch_routes` gRPC stream is backed by a broadcast channel. Slow consumers that
fall behind the channel buffer are disconnected with a "watch stream fell behind; reconnect"
error. The BGP control plane is unaffected — this is management-API only — but it means
`watch_routes` cannot be used for guaranteed-delivery use cases (audit logs, secondary RIB
sync, compliance recording).

If guaranteed delivery is needed: replace the broadcast channel with a persistent queue
(e.g. bounded mpsc with back-pressure) and a snapshot + delta replay protocol so reconnecting
clients can resume from a known position. Alternatively, document the limitation clearly
and recommend clients use the snapshot endpoint (`list_routes`) for durable reads.

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

### Graceful Restart — known gaps (2026-06-22)

RFC 4724 Phase 1 and Phase 2 are fully implemented and e2e verified against GoBGP.
The `daemon.rs` GR-module split and the initial EOR-prune/re-termination test gaps
were resolved 2026-06-22 — see CHANGELOG.md. The following gaps remain, ordered by
priority.

**1. `mark_stale_and_repropagate` performance at full-table scale**

When a GR-capable peer disconnects, `mark_stale_and_repropagate` iterates every
NLRI from that peer and calls `rib_mut()` in a loop (repeated `Arc::make_mut`).
For the DDoS blackhole use case (tens of prefixes, handful of peers) this is
negligible. For a full-table iBGP peer (~800k prefixes) this loop would be
noticeable — potentially hundreds of milliseconds under the write lock, causing
hold-timer pressure on other peers.

The right fix if full-table peers are ever needed: replace eager `Arc::make_mut`
marking with a generation-counter or stale-epoch approach — routes are considered
stale if their epoch < the current GR epoch for that peer, computed lazily at
best-path selection time rather than eagerly on disconnect.

**2. EOR-prune e2e test timing margin**

`gr_phase2_eor_prunes_stale_routes_not_refreshed_by_peer` uses a 15 s
`wait_for_established` timeout with a 2 s `connect_retry_time`. On a fast machine
this is comfortable (first retry fires ≤2 s after reconnect, BGP exchange adds
~1 s), but on a loaded CI runner the margin is tighter than ideal. If this test
shows intermittent failures in CI, increase `connect_retry_time` to 3 s and the
timeout to 20 s.

**3. `PeerConfig` struct literal proliferation**

Adding `connect_retry_time: Option<u16>` required inserting `connect_retry_time: None`
into 30+ test struct literals via sed. Every future optional field on `PeerConfig`
will cost the same. Consider introducing a `peer_config(addr, remote_as)` test
helper (in `daemon.rs` test module) that fills sensible defaults, so call sites
only specify the fields under test. `Ipv4Addr` not implementing `Default` blocks
a derive — the helper is the right answer.

**4. GR deadline timer re-polls on every event loop iteration**

The `tokio::select!` branch for deadline expiry calls
`state.gr_deadlines.values().copied().min()` on every poll. When the map is empty
(steady state) this is a no-op iteration and resolves to `pending()`. For a large
number of simultaneous GR windows (unlikely in production) this becomes a tighter
loop than necessary. If needed, cache the next deadline as `Option<Instant>` on
`DaemonState` and invalidate it only on GR window insert/remove.

**5. RFC 4724 §3 SHOULD: suppress GR capability when peer restart_time = 0**

When the peer's OPEN carries a GracefulRestart capability with `restart_time = 0`,
pathvectord currently logs a warning but still advertises its own GR capability.
RFC 4724 §3 says we SHOULD suppress our advertisement in this case to avoid the
overhead of a feature the peer cannot use. Low priority — correctness is unaffected.

`on_gr_deadline_expired` never re-propagating IPv6 withdrawals to other peers
(found while closing the IPv6 export-policy gap) — resolved 2026-07-03, see
CHANGELOG.md. Added a v6 re-propagation loop mirroring
`repropagate_after_stale_mark_v6`/`prune_stale_nlri_v6`'s existing shape,
export-policy-aware, gated on `ipv6_capable_peers`.

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

- **MD5 auth for IPv6 peers** — `pathvector-sys`'s `TcpMd5Sig` struct is built on
  `sockaddr_in` and returns `Unsupported` for an IPv6 peer; needs a separate
  `sockaddr_in6`-based ABI path. Split out from the now-shipped IPv6 BGP
  transport work (2026-07-05): the listener binds and dials both families,
  `PeerConfig`/`DaemonState`/gRPC/CLI are all dual-stack, and
  `pathvector-e2e/tests/ipv6_transport.rs` proves a session reaches
  Established over a real IPv6 TCP connection — but an IPv6 peer configured
  with `md5_password` will currently fail to apply the signature.

- **Dynamic neighbors** — accept BGP sessions from peers not explicitly configured,
  filtered by a source prefix range (e.g. `dynamic_peer_prefix = "10.0.0.0/24"`).
  Common at IXPs where the peer list changes without operator intervention. Requires
  the TCP listener to look up the peer by source IP or fall back to a dynamic
  neighbor template rather than failing with "unknown peer".

- **Peer groups** — a named config template applied to multiple peers; changing one
  field on the group propagates to all members without restarting unaffected sessions.
  Maps cleanly to a `[[peer_groups]]` TOML table and a `peer_group: Option<String>`
  field on `PeerConfig`.

- **AS path regex in policy** — match routes by AS path pattern
  (`^65001 ` for routes originated by AS 65001, `_65002_` for transit through AS 65002).
  Requires a regex condition in `pathvector-policy`; the `regex` crate is the natural
  choice. Most production policy engines expose this as a first-class condition.

- **IPv6 import policy per-AFI config** — currently IPv6 import policy is accept-all;
  per-AFI policy config (per-peer `import_default_v6`) is deferred.

IPv6 export policy gap — `propagate_prefix_v6` never consulted `export_policies`,
unlike `propagate_prefix` (IPv4) — resolved 2026-07-02 — see CHANGELOG.md.
`propagate_prefix_v6` now takes an `export_policy: &Policy<Route<Ipv6Addr>>`
parameter and evaluates it exactly like the IPv4 path, via a new
`export_policies_v6` map (mirroring `import_policies_v6`; there is still no
separate `export_default_v6` config knob — the single `export_default` value
governs both families). This also closes the matching RFC 9234 gap: OTC egress
block/attach now applies to IPv6 routes, not just IPv4.

Event-loop integration test for the reconnect capability-refresh path (both the
RFC 4724 R-bit and RFC 9234 Role surviving reconnect via
`SessionCommand::SetCapabilities`) resolved 2026-07-02 — see CHANGELOG.md.

`reapply_import_policy` IPv6 counterpart and `cluster_id` configuration guidance
resolved 2026-06-19 — see CHANGELOG.md.

**Remaining:** Add a callout to `pathvectord/README.md` alongside the `is_route_reflector` config example: "if you run multiple RR clusters, set distinct `cluster_id` values per cluster — sharing a `cluster_id` across clusters causes CLUSTER_LIST loop detection to fire incorrectly."

---

## pathvector-client

### Remaining

- `serde` feature: `Serialize`/`Deserialize` derives are gated but not yet
  implemented on the domain types (blocked on deciding JSON schema conventions)
- Policy introspection RPC (`ListTerms`, `EvalRoute`) — `reapply_import_policy` is now wired to export propagation (done 2026-06-09); the RPC itself is not yet implemented

---

## Cross-cutting

### Design patterns / dependency-inversion improvements

Two remaining changes that improve testability or robustness without over-engineering.
(Item 1, the `RibSnapshot` split, was resolved 2026-06-11 — see CHANGELOG.md.)

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

3. **`RibView` trait for `propagate_prefix_v6`** (`pathvectord`) — `propagate_prefix` (IPv4) already uses `&impl RibView<Ipv4Addr>`; `propagate_prefix_v6` still takes `&LocRib<Ipv6Addr>` (concrete type). Mirror the IPv4 abstraction so the IPv6 path is equally testable. Useful before best-path selection grows more complex (ECMP, route reflector client preference, etc.).

### Internal documentation on hard algorithms

The implementation has good API-level doc comments but the non-obvious logic
lacks prose explanation. A new contributor should not need to reconstruct the
RFC in their head to understand the code. Priority targets:

- **Best-path selection** (`pathvector-rib/src/best_path.rs`) — annotate each
  step with the RFC 4271 §9.1 section it implements and why the tie-breaking
  order is what it is
- **RIB eviction on `Terminated`** (`pathvectord/src/daemon.rs`, `on_terminated`)
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

#### Memory

Resolved by `rib-memory-opt`, 2026-06-17 — see CHANGELOG.md for the full benchmark table.
No further memory audit planned unless profiling on a real multi-peer internet table
(not synthetic) reveals a regression.

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

2. **NLRI batching in outbound UPDATEs** — shipped 2026-06-20 (see CHANGELOG.md: Cross-UPDATE
   NLRI coalescing in outbound pipeline). RIB convergence improved from 4.46s to 2.88s
   (M2 Max, 1.13M prefixes).

   **Remaining test coverage risks (2026-06-20):**

   - `event_loop_drain_coalesces_rapid_burst` relies on a 100ms sleep to give
     the event loop time to process all 10 events before the assertion runs.
     This is timing-dependent and not deterministic. To make it robust, use
     Tokio's `time::pause()` + `time::advance()` to control the scheduler, or
     replace the sleep with a channel-based done signal from within the loop.

   - No wire-level UPDATE count measurement exists at the e2e layer. The
     `TwoPeerHarness` tests verify that all prefixes arrive at the sink, but
     they cannot assert that those prefixes arrived in fewer UPDATE messages
     than were announced. To close this gap: add a counter to `DaemonState`
     (`outbound_update_count: AtomicUsize`) gated behind `#[cfg(test)]`, or
     extend the MRT harness to accept a second peer and count inbound BGP
     UPDATEs at that peer's TCP stream.

3. **Inbound convergence time audit** — NLRI batching improves the outbound path
   (announcement throughput), but RIB convergence time is dominated by the inbound path:
   parsing incoming UPDATEs, inserting into AdjRibIn, running best-path, and updating
   LocRib. Batching alone will not close the gap with BIRD on convergence. BIRD's
   primary convergence advantage comes from:

   - **Attribute hash-consing (rta deduplication)** — BIRD stores one canonical `rta`
     struct per unique attribute set and reference-counts it. Identical AS paths across
     thousands of routes share one allocation. Our `Route` struct clones `Vec<Asn>` on
     every insert. Adding interning at the `AsPath` level in `pathvector-types` would
     reduce allocation pressure on the inbound hot path.
   - **Filter bytecode** — BIRD compiles policy filters to a bytecode VM rather than
     evaluating a tree of conditions. Policy evaluation on the inbound path currently
     walks the `Vec<Box<dyn EvaluateTerm>>` chain for every route. At 1M+ routes this
     adds up.
   - **Per-prefix lock granularity** — BIRD updates prefixes concurrently; our event
     loop holds a single `RwLock<DaemonState>` for the entire duration of each UPDATE.

   Recommended audit order:
   1. Profile `on_route_update` under MRT load to identify the dominant cost (allocation
      vs. best-path vs. policy eval vs. lock contention).
   2. Prototype `AsPath` interning — an `Arc<Vec<Asn>>` or a global intern table — and
      measure impact on `loc_rib_insert` criterion benchmark.
   3. Evaluate per-prefix or per-peer lock granularity as a follow-on if profiling shows
      lock contention is meaningful.

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

`pathvector-rib` benchmarks (`select_best`, `loc_rib_insert`, `outbound_pipeline`) shipped
2026-06-18 — see CHANGELOG.md.

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

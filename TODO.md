# TODO

Tracked items that are intentionally deferred — known gaps, planned features,
and protocol steps that require components not yet built. Each entry notes
which crate it belongs to and why it was deferred.

---

## Prioritized next steps

Items are grouped by what they unlock, not just by effort. A small correctness
fix that unblocks a larger feature is worth doing before the feature itself.

### Tier 1 — Small scope, high correctness or coverage value — **Done (2026-06-09)**

**1. Advertise `MultiProtocol(IPv4_UNICAST)` capability** (`pathvectord`) — **Done (2026-06-09)**
Added `Capability::MultiProtocol(AfiSafi::IPV4_UNICAST)` to the session
config. Brings the OPEN into RFC 4760 compliance and causes GoBGP to send IPv4
routes via MP_REACH_NLRI, exercising the MP code path against a real peer for
the first time. Also the mandatory first step before advertising IPv6 capability.

**2. Wire `reapply_import_policy` → export propagation** (`pathvectord`) — **Done (2026-06-09)**
Added `DaemonState::set_import_default` and `set_export_default` methods that
update the relevant policy, call `reapply_import_policy`, and immediately
propagate any Loc-RIB changes to all established peers via `propagate_prefix`.
Exposed as `SetImportDefault` / `SetExportDefault` gRPC RPCs in the new
`PolicyService`. Two soft-reconfig e2e tests confirm the full chain
(`e2e/tests/policy.rs`: `soft_reconfig_import_accept_installs_route`,
`soft_reconfig_export_accept_propagates_to_sink`).

### Tier 2 — Medium scope, architectural or user-facing value

**3. RFC 7606 revised UPDATE error handling** (`pathvector-session`, `pathvectord`) — **Done (2026-06-10)**
`UpdateDecodeOutcome::Partial` replaces the flat `Err(CodecError)` path for
per-attribute errors. `BgpMessage::MalformedUpdate` carries the cleaned UPDATE
plus per-attribute `AttributeDecodeError` entries. The transport layer applies
the RFC 7606 §5 policy table: treat-as-withdraw (ORIGIN, AS_PATH, NEXT_HOP,
LOCAL_PREF, MP_REACH_NLRI) or attribute-discard (all optional non-mandatory
attributes). Duplicate type codes in a single UPDATE are detected and treated as
withdraw (RFC 7606 §7.3). Good attributes in the same UPDATE survive alongside a
discarded attribute. `make_treat_as_withdraw` converts announced NLRIs and any
decoded MP_REACH_NLRI prefixes into proper withdrawals. The session stays up in
all cases; malformed-attribute events are `tracing::warn!`-logged with type code,
detail, and RFC 7606 policy. See RFC_REQUIREMENTS.md §RFC 7606 for full coverage.

**4. CLI tool (`pathvector`)** (new crate, uses `pathvector-client`) — **Done (2026-06-09)**
Implemented as `pathvector/` workspace member. Subcommands: `peer list`,
`peer get`, `route list [--peer]`, `route best`, `route candidates`,
`policy set-import`, `policy set-export`, `route originate`, `route withdraw`,
`route list-originated`, `watch routes [--peer]`, `watch peers`, and `dashboard`
(live ratatui TUI). Global `--address` flag + `PATHVECTOR_ADDRESS` env var select
the daemon endpoint. `watch routes` and `watch peers` stream events to stdout until
Ctrl-C using `tokio::select!` on the stream and `tokio::signal::ctrl_c()`.

**5. Dashboard: replace polling with streaming** (`pathvector`) — **Done (2026-06-11)**
`run_dashboard` now subscribes to `WatchPeers` and `WatchRoutes` streaming RPCs before
entering raw mode. A `spawn_blocking` thread bridges crossterm's blocking keyboard poll
into the async `tokio::select!` loop alongside `peer_stream.next()` and
`route_stream.next()`. `DashboardState::apply_peer_event` and `apply_route_event` are
pure state-mutation methods that upsert / remove entries in-place. The status bar shows
`● Live` (green) instead of a stale timestamp; connection errors replace the live
indicator with the error string. `MockDaemonClient` grows `watch_routes`/`watch_peers`
impls returning empty streams. 15 unit tests cover all event variants and error paths.
`BoxStream<T>` type alias exported from `pathvector-client` allows naming the stream type
in bindings, struct fields, and `dyn` contexts. `DaemonClient` trait extended with
`watch_routes` and `watch_peers`.

**Remaining dashboard gap:** `last_error` is a single `Option<String>` so two simultaneous
failures (one from each stream) overwrites the first error. In practice both streams fail
together ("daemon down") so the second message is equally informative. Fix requires UI
layout decision; deferred.

**6. IPv6 RIB — dual-stack** (`pathvectord`) — **Done (2026-06-12)**
Full dual-stack BGP. Inbound: parallel `LocRib<Ipv6Addr>` / `AdjRibIn<Ipv6Addr>`
tables in `DaemonState`; `handle_update` routes `AfiSafi::IPV6_UNICAST`
MP_REACH_NLRI and MP_UNREACH_NLRI to them; `sync_received` counts both AFIs;
`on_established` resets v6 AdjRibIn; `on_terminated` withdraws v6 routes.
Outbound: parallel `AdjRibOut<Ipv6Addr>` per peer; `propagate_prefix_v6` applies
`prepare_outbound_v6` (AS_PATH prepend + NEXT_HOP rewrite for eBGP);
`flush_updates_v6` packs MP_UNREACH_NLRI and MP_REACH_NLRI UPDATE messages;
`propagate_to_all_peers_v6` wires the full pipeline; `on_established` sends a
v6 full-table dump; `on_route_update` propagates affected v6 NLRIs.
Config: `local_ipv6: Option<Ipv6Addr>` in `DaemonConfig` — required for eBGP
next-hop rewrite (iBGP is pass-through and works without it).
Capability: `MultiProtocol(IPV6_UNICAST)` advertised in OPEN.
gRPC: `list_routes` and `watch_routes` include v6 routes via `route_v6_to_proto`.
IPv6 import policy is accept-all; per-AFI policy config is deferred.
Tests: 10 new unit tests covering announce, withdraw, AdjRibIn storage, mixed
v4+v6 UPDATE, eBGP next-hop rewrite, eBGP suppression without `local_ipv6`,
withdraw-on-disappear, full-table dump on Established, end-to-end propagation.

**10. ROUTE-REFRESH receive guard** (`pathvector-session`) — **Done (2026-06-10)**
ROUTE-REFRESH received in `Established` is now gated on capability negotiation.
If both sides advertised `RouteRefresh` during OPEN, the message is accepted
(session stays up; full re-advertisement is deferred as a future item).
If not negotiated, the FSM sends FSM Error subcode 3 and tears down the
session. The send direction is a no-op because pathvector never initiates
ROUTE-REFRESH today.
Tests: `test_route_refresh_with_capability_is_accepted`,
`test_route_refresh_without_capability_sends_fsm_error_subcode_3`.

**11. FSM error subcodes 1/2/3** (`pathvector-session`) — **Done (2026-06-10)**
Added `FsmErrorOpenSent`, `FsmErrorOpenConfirm`, `FsmErrorEstablished` variants
to `NotificationError` (wire: code 5, subcodes 1/2/3). The three `_ => vec![]`
wildcards in `on_open_sent`, `on_open_confirm`, and `on_established` now each
send the correct NOTIFICATION and tear down the session when an unexpected
message type arrives. Closes three `❌` rows in RFC_REQUIREMENTS.md.
Tests: `test_unexpected_message_in_open_sent_sends_fsm_error_subcode_1`,
`test_unexpected_message_in_open_confirm_sends_fsm_error_subcode_2`,
`test_unexpected_message_in_established_sends_fsm_error_subcode_3`.

### Tier 3 — Larger scope, important but not blocking

**7. BIRD 2 interoperability**
BIRD is the most widely deployed open-source BGP implementation (IXPs, hosting
providers, research networks) and is stricter than GoBGP about RFC compliance.
Running the existing e2e suite against BIRD would surface any GoBGP-specific
leniency the implementation currently relies on.

Infrastructure needed:
- `e2e/Dockerfile.bird` — Alpine image with `bird2` package; tiny, fast boot
- `e2e/bird.conf.tmpl` — per-test config template (router id, AS, neighbor, filter)
- `BirdHarness` in `e2e/src/lib.rs` or a `peer: PeerKind` enum on the existing `Harness`
- CLI wrapper: `birdc show route` / `birdc show protocols all` for route/state queries

The `Harness` abstraction generalises cleanly — the same session/route/policy/auth
test scenarios should pass against BIRD unchanged if the protocol implementation is
correct. Any test that passes GoBGP but fails BIRD is a real bug worth fixing.

Distinct value: BIRD enforces UPDATE attribute ordering and rejects malformed
attributes that GoBGP silently accepts. Most likely surface for hidden bugs.

**8. FRR (FRRouting) interoperability**
FRR is what Cloudflare, Facebook, and most modern network hardware runs for BGP.
The official `frrouting/frr` Docker image is freely available. More complex than
BIRD (needs `zebra` + `bgpd` daemons inside the container) but the most
production-realistic peer available without licensing.

Infrastructure needed:
- `e2e/Dockerfile.frr` or use `frrouting/frr` image directly with a mounted config
- `frr.conf` / `daemons` file template (enable `bgpd=yes`, disable others)
- CLI wrapper: `vtysh -c "show bgp summary"` / `vtysh -c "show bgp ipv4 unicast"`

Distinct value: FRR has the most complete RFC 7606 error-handling of any open-source
implementation — it would immediately expose the current "any decode error resets
the session" gap. Also exercises large-community handling and NEXT_HOP validation
edge cases that GoBGP is lenient about.

**9. Arista cEOS (commercial, later)**
cEOS is Arista's containerized EOS, freely available with registration from the
Arista portal. Runs as a proper OCI container. Most accessible commercial router OS
for interop testing — no VM required.

Add once BIRD and FRR are solid. Requires an Arista account; cannot be pulled
anonymously in public CI. Gate behind a `CI_ARISTA_IMAGE` env var so it runs only
when the image is available.

**10. Criterion benchmark suite** ✅ Done (2026-06-14)
`pathvector-rib` has three criterion benchmark groups (`select_best`, `loc_rib_insert`,
`outbound_pipeline`). Baseline on M2 Max:

| Benchmark | Small | Medium | Large |
|---|---|---|---|
| `select_best` | 4.9 ns (2 candidates) | 35 ns (10) | 526 ns (100) |
| `loc_rib_insert` | 309 ns (10k prefixes) | 293 ns (100k) | 802 ns (500k) |
| `outbound_pipeline` (minimal) | 242 ns (1 peer) | 1.61 µs (10) | 8.59 µs (50) |
| `outbound_pipeline` (dense) | 387 ns (1 peer) | 2.64 µs (10) | 14.4 µs (50) |

Run with `cargo bench -p pathvector-rib`. HTML reports in `target/criterion/`.

**11. Adversarial input / NOTIFICATION path testing**
RFC 7606 (item 3) is the prerequisite — once the error handling architecture
exists, injecting malformed UPDATEs and NOTIFICATIONs over real TCP becomes
the natural way to verify it. Before RFC 7606 there is less to test.

---

## General
~~Download Relevant RFC's to each module.~~
~~Generate a list of requirements from the RFC's.~~
~~Check whether or not the each module currently meets these requirements.~~
**Done** — `RFC_REQUIREMENTS.md` tracks every implemented RFC, its requirements, owning module,
implementation status, and verified-by test citations.

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
- _Gap (closed 2026-06-12)_: outbound batching now has property coverage in
  `outbound::prop_tests`. Four proptests covering `flush_updates` (IPv4) and `flush_updates_v6`
  (IPv6): `prop_flush_updates_no_message_exceeds_max_len`, `prop_flush_updates_all_announces_sent`,
  `prop_flush_updates_all_withdrawals_sent`, `prop_flush_updates_v6_no_message_exceeds_max_len`.

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
- _Gap_: BIRD and FRR interoperability (stricter RFC compliance than GoBGP). See Tier 3, items 7 and 8.

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

**Phase 1 — `pathvector-session` codec round-trips** ✓ Done
All four message types (OPEN, UPDATE, NOTIFICATION, KEEPALIVE, ROUTE-REFRESH) have round-trip
proptests at both the `BgpMessage::encode/decode` layer (`message/prop_tests.rs`) and the
`BgpCodec` framing layer (`framing/prop_tests.rs`). Full capabilities, path attributes, and all
`NotificationError` sub-families are exercised. `prop_decode_never_panics` covers both layers.
The generators exposed a real round-trip constraint: `Unknown` sub-variants must exclude codes that
the decoder maps to named variants — constrained accordingly.

**Phase 2 — `pathvector-rib` best-path invariants** ✓ Done (2026-06-09)
Step-by-step isolation proptests in `pathvector-rib/src/best_path.rs::prop_tests`:
- `prop_select_best_winner_has_highest_local_pref` — winner LP ≥ all others (step 2)
- `prop_select_best_missing_local_pref_treated_as_100` — None → 100 default (step 2)
- `prop_select_best_winner_has_shortest_as_path` — winner len ≤ all others (step 4)
- `prop_select_best_winner_has_lowest_origin` — winner origin ≤ all others (step 5)
- `prop_select_best_winner_has_lowest_med` — winner MED ≤ all others, None=0 (step 6)
- `prop_select_best_ebgp_beats_ibgp` — eBGP beats iBGP even with lower peer IP (step 7)
- `prop_select_best_lower_peer_ip_wins_on_full_tie` — full-tie tiebreaker (step 10)
- `prop_select_best_non_empty_returns_some`, `prop_select_best_winner_is_in_candidates`
  (structural invariants)
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

**Phase 5 — `pathvector-e2e` Docker-based end-to-end suite** ✓ Done (2026-06-09)
Both gobgpd and pathvectord run as Linux containers on an isolated Docker bridge network
per test. BGP (port 179) is container-to-container — the macOS Docker Desktop TCP proxy
never touches it. Only pathvectord's gRPC port is mapped to the host for `PathvectorClient`.

Infrastructure committed on branch `e2e` (commit `19a8605`):
- `e2e/Dockerfile` — GoBGP 4.6.0 Alpine image (Linux arm64/amd64, no macOS prebuilt needed)
- `e2e/Dockerfile.pathvectord` — multi-stage Rust build; debian:bookworm-slim runtime
- `e2e/docker-compose.yml` — manual dev environment with fixed `172.20.0.0/24` subnet
- `e2e/src/lib.rs` — `Harness` using testcontainers-rs 0.23; per-test `docker network create/rm`;
  `docker inspect` for container IP; `docker exec` for gobgp CLI

20 tests passing across 4 files:
- `routes.rs` (6): `announced_route_appears_in_rib`, `list_candidates_returns_peer_route`,
  `multiple_routes_all_installed`, `partial_withdrawal_leaves_others_intact`,
  `unknown_prefix_returns_none`, `withdrawn_route_removed_from_rib`
- `session.rs` (6): `list_peers_includes_gobgp_peer`, `peer_state_fields_correct_after_established`,
  `session_reaches_established`, `wait_for_established_respects_deadline`,
  `wait_for_route_respects_deadline`, `wait_for_route_withdrawn_respects_deadline`
- `outbound.rs` (4): `announced_route_propagates_to_sink`, `multiple_routes_all_propagate_to_sink`,
  `withdrawn_route_removed_from_sink`, `source_route_visible_in_pathvectord_rib`
- `policy.rs` (4): `no_import_policy_rejects_ebgp_prefix`, `explicit_import_accept_installs_ebgp_prefix`,
  `no_export_policy_suppresses_advertisement_to_peer`, `explicit_export_accept_propagates_to_sink`

Remaining e2e work:
- **Outbound advertisement tests** — **Done (2026-06-09).** Two-peer topology:
  GoBGP-source (AS 65003) → pathvectord (AS 65002) → GoBGP-sink (AS 65001).
  `TwoPeerHarness` in `e2e/src/lib.rs`; four tests in `e2e/tests/outbound.rs`
  cover: single prefix propagation, multi-prefix, withdrawal, and management-API
  visibility. `write_daemon_config` generalized to accept a slice of peers.
- **Import/export-policy reject tests (RFC 8212)** — **Done (2026-06-09).**
  `Harness::new_rfc8212()` configures pathvectord with no policy on the peer;
  `TwoPeerHarness::new_no_export_policy()` configures import-accept + no export.
  Four tests in `e2e/tests/policy.rs` prove both directions: routes are blocked
  without an explicit policy and flow correctly with one.
- **Fault injection / chaos tests** — inject TCP resets mid-session, corrupt
  bytes at the framing layer, and drop packets during the OPEN exchange; verify
  the FSM recovers cleanly rather than wedging. Prerequisite: RFC 7606 error
  handling (Tier 2, item 3) so there is a defined response to malformed input.
- **Backpressure / sustained churn tests** — verify the channel-full stall
  detection and recovery under sustained route churn, not just a single crafted
  test case. Candidate scenario: ExaBGP replaying a partial MRT dump at high
  rate while a second peer's UPDATE channel is artificially constrained.
- **GitHub Actions e2e workflow** — **Done (2026-06-09).** Separate `e2e` job in
  `.github/workflows/ci.yml` on `ubuntu-latest` (Docker pre-installed). Uses
  `docker/setup-buildx-action` + `docker/build-push-action` with `type=gha` layer
  caching (separate scopes for `gobgpd` and `pathvectord` images). GoBGP image is a
  cache hit on repeat runs. `test` and `msrv` jobs now pass `--exclude pathvector-e2e`
  so the crate is not exercised without its required images. A `.githooks/pre-push` hook
  (installed via `just install-hooks`) runs `just e2e` locally before each push.
- **IPv6 interoperability (GoBGP)** — **Done (2026-06-12).** Three new e2e tests confirm the
  full IPv6 wire path against GoBGP 4.6.0:
  - `routes.rs::announced_v6_route_appears_in_rib` — GoBGP announces `2001:db8::/32` via
    MP_REACH_NLRI; pathvectord installs it; `get_best_route` returns it with correct attributes
  - `routes.rs::withdrawn_v6_route_removed_from_rib` — GoBGP withdraws via MP_UNREACH_NLRI;
    pathvectord removes it from LocRib_v6
  - `outbound.rs::originated_v6_route_propagates_to_gobgp` — pathvectord originates
    `2001:db8:1::/48`; GoBGP receives it via MP_REACH_NLRI with NEXT_HOP = `2001:db8::2`
    (eBGP rewrite from `local_ipv6`)
  Also fixed: `get_best_route` gRPC handler now queries `loc_rib_v6` for IPv6 prefixes;
  `originate_route`/`originate_routes` dispatch to `originate_route_v6` for IPv6 prefixes.

- **BIRD interoperability** — add a second peer implementation. BIRD is stricter about RFC
  compliance than GoBGP (it's the reference implementation for many IXP route servers) and
  will catch things GoBGP tolerates. A `e2e/Dockerfile.bird` wrapping the official BIRD
  package + `e2e/fixtures/bird.conf` is all that's needed; the `Harness` architecture already
  supports multiple peer images. Target: run the same 10 session + route tests against BIRD
  to confirm the handshake and UPDATE exchange is broadly interoperable, not just GoBGP-specific.

## pathvector-rib

### Best-path selection — missing decision steps

RFC 4271 §9.1 defines a 10-step decision process. The current implementation
covers steps 2, 3/7, 4, 5, 6, 9, and 10. The two remaining steps require
external information not available at the RIB layer:

| Step | Criterion | Blocked on |
|---|---|---|
| 1 | Prefer routes with a reachable next-hop | FIB integration — the RIB needs to know which next-hops are reachable |
| 8 | Prefer locally originated routes | Peer session type — the RIB needs to know whether a route was originated locally vs learned from a peer |

### Trait-based RIB and policy seams

**`RibView` seam — Done (2026-06-11).** `pathvector-rib` now exports a `RibView<A>` trait
with a single `best(&self, nlri) -> Option<&Route<A>>` method. `LocRib<A>` implements it.
`propagate_prefix` in `pathvectord` is now generic over `impl RibView<Ipv4Addr>` instead
of taking `&LocRib<Ipv4Addr>` directly. A `StubRibView(Option<Route<Ipv4Addr>>)` test
double in `pathvectord`'s test module (3 tests) demonstrates that the Update-Send Process
can be driven with injected best routes — no RIB construction or peer setup required.

**Remaining seams** — `pathvectord` still depends concretely on `AdjRibIn`, `AdjRibOut`,
and `Policy<Route<Ipv4Addr>>` at the `DaemonState` level. Full inversion (allowing
third-party RIB or policy implementations) would require `impl RibStore` + `impl PolicyEngine`
traits in a new thin `pathvector-core` crate, or accepting upward dependency in
`pathvector-rib`/`pathvector-policy`. Deferred until the embedding use-case becomes concrete.

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

### FIB integration (Netlink / kernel route installation)

Routes are correctly selected by `select_best` and stored in `LocRib`, but never
installed into the kernel's forwarding table. pathvectord cannot actually forward
packets — it is a BGP process, not yet a BGP router.

FIB integration requires:
- A `FibManager` component that subscribes to `LocRib` best-route changes
  (via `RouteEvents`) and translates them into Netlink `RTM_NEWROUTE` /
  `RTM_DELROUTE` messages
- `rtnetlink` crate (or raw Netlink sockets) for kernel interaction
- A configurable route table number and protocol ID (to avoid stomping on static
  or OSPF routes)
- Route ownership tracking: when pathvectord exits cleanly, withdraw all installed
  routes; on crash, the kernel automatically removes routes with the daemon's
  protocol ID if `NLM_F_CREATE` was used with a protocol tag

This is the single most impactful gap between "BGP implementation" and "BGP router".
It also unblocks best-path step 1 (next-hop reachability via IGP cost).

FIB integration is Linux-specific. macOS and other platforms would require a
`#[cfg]`-gated stub that logs installed/withdrawn routes without touching the kernel.

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

- ~~MD5 authentication (RFC 2385) — TCP-MD5 socket option for eBGP peering~~ **Done (2026-06-13).** `md5_password: Option<String>` TOML field → `SessionConfig` → `apply_tcp_md5sig` (Linux `setsockopt TCP_MD5SIG`) on the outbound `TcpSocket` before `connect()` and on the BGP listener socket after `bind()`. No-op with `warn!` on non-Linux (macOS dev). IPv6 peer MD5 deferred.
- Documentation: add MD5 interop recipe to `LOCAL_INTEROP.md` and refresh `TESTING.md` with MD5 safety section, `pathvector-sys` proptest table, and full 41-test e2e scenario table — **Done (2026-06-13).**
- BGP-SEC (RFC 8205) — cryptographic path validation; further out, but worth noting alongside MD5 as the broader authentication story
- ~~Connection collision detection~~ — **Done (2026-06-11).** `FsmInput::CollisionDetected` resets the FSM to Active without emitting `SessionTerminated` (no RIB churn). The transport layer compares `local_bgp_id` vs `peer_bgp_id` (from the stored peer OPEN) and either adopts the incoming stream or drops it. `pathvectord` spawns a `TcpListener` on `bgp_port` (default 179, configurable) and routes accepted connections to per-peer sessions via `SessionCommand::IncomingConnection`. Tests: `test_collision_detected_in_open_sent/open_confirm_resets_to_active`, `test_collision_local_wins_adopts_incoming`, `test_collision_peer_wins_keeps_outbound`.
- Graceful Restart FSM behaviour (RFC 4724) — capability is parsed and forwarded in `SessionInfo`, but the FSM does not yet act on it (hold forwarding state, stale route timer)
- NOTIFICATION support for Graceful Restart (RFC 8538) — allows sending CEASE NOTIFICATION during the GR window without tearing down the restart; extends RFC 4724; depends on Graceful Restart FSM
- Enhanced Route Refresh (RFC 7313) — adds `ORF_BEGIN` / `ORF_END` markers so the receiver knows when a full re-advertisement is complete; extends RFC 2918; currently codec-only
- Extended admin shutdown communication (RFC 9003) — extends CEASE NOTIFICATION (RFC 4486) with a UTF-8 freetext reason string (max 128 bytes); small addition on top of existing CEASE infrastructure
- BGP Role attribute / route leak prevention (RFC 9234) — `ROLE` OPEN capability and `ONLY_TO_CUSTOMER` community; automatic leak detection at the session layer; requires role config per peer (`provider`, `customer`, `rs`, `rs-client`, `peer`)
- Per-peer hold timer and keepalive interval — currently held in `SessionConfig` at a fixed value; should be configurable per peer in `PeerConfig` with a global fallback in `[daemon]`
- Outbound ROUTE-REFRESH trigger — send a `ROUTE-REFRESH` message to a peer to request their full table re-advertisement (protocol-level inbound soft reset); currently soft reset is API-driven only; requires RFC 2918 capability negotiation guard (already present)

### Hold timer expiry — active FSM enforcement — **Done**

The hold timer is fully implemented and wired. `wait_for_input` fires
`HoldTimerExpired` when `hold_deadline` elapses; `on_established` sends
`NOTIFICATION(HoldTimerExpired)`, stops timers, closes TCP, and emits
`SessionTerminated`. KEEPALIVE and UPDATE receipt call `reset_hold_if_active()`
to restart the deadline. Covered by `test_hold_timer_expired_in_established`,
`test_keepalive_message_in_established_resets_hold_timer`, and the interop test
`test_hold_timer_fires_terminates_session` over real TCP.

### RFC 7606 — Revised UPDATE error handling

Currently any decode error in `BgpCodec` / `UpdateMessage::decode` propagates as a
`CodecError`, which the transport layer always treats as a session reset (send
NOTIFICATION, close TCP). RFC 7606 requires a finer-grained response depending on
which attribute is malformed:

- **Session reset** — missing well-known mandatory attribute; malformed AS_PATH (some
  subcases)
- **Treat as withdraw** — malformed ORIGIN, NEXT_HOP, MP_REACH_NLRI; the NLRIs
  carried by the bad UPDATE are withdrawn but the session stays up
- **Attribute discard** — malformed optional non-transitive attributes; the attribute
  is silently dropped, the rest of the UPDATE is processed normally

**Why this matters:** session reset on a malformed optional attribute is operationally
disruptive — a single bad community value in a large-scale peer's announcement brings
down the session rather than dropping the one route. Real networks rely on the lenient
behaviour.

**Architectural impact:** this requires changes at multiple layers:

1. `BgpCodec` / `UpdateMessage::decode` — instead of `Err(CodecError)` on every
   malformed attribute, return a richer type that carries the decoded-so-far UPDATE
   together with a per-attribute error and its RFC 7606 policy
   (`SessionReset | TreatAsWithdraw | AttributeDiscard`)
2. `Session<T>` transport layer — currently maps any codec error to `TcpFailed`;
   must instead inspect the error policy and act accordingly: log + continue for
   `AttributeDiscard`, log + withdraw NLRIs for `TreatAsWithdraw`, send NOTIFICATION
   for `SessionReset`
3. New `SessionEvent` variant (or extend `RouteUpdate`) to surface discarded
   attributes and treat-as-withdraw decisions to `pathvectord` for logging

This is an architectural change that touches the codec, the transport layer, and the
daemon event loop. It is best addressed before the codec grows further (every new
attribute decode arm will otherwise inherit the session-reset default). See
RFC_REQUIREMENTS.md §RFC 7606 for the per-attribute policy table.

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
  after a peer disconnects until the next reconnect/snapshot. Same gap as the
  `on_route_update` / `set_import_default` omission fixed 2026-06-13. Fix:
  call `emit_route_events(&prev_prefixes)` after `withdraw_peer` (routes that
  lost their only candidate emit Withdrawn; routes promoted to another peer's
  candidate emit Announced with the new best). Tests: assert that
  `route_tx` receives Withdrawn events for each route removed on termination.

- **Split `pathvectord/src/main.rs`** — **Done (2026-06-12).** The 5865-line file was split
  into three modules:
  - `src/main.rs` (31 lines) — binary entry point only
  - `src/daemon.rs` (5240 lines) — `DaemonState`, `RibSnapshot`, `handle_update`,
    `reapply_import_policy`, `run`, `run_bgp_listener`, and all daemon/event/prop tests
  - `src/outbound.rs` (605 lines) — all outbound pipeline functions (`propagate_prefix*`,
    `flush_updates*`, `route_*_to_attributes*`) + their unit and property tests
  All 214 unit tests pass; `cargo clippy -D warnings` is clean.

- **IPv6 import policy (RFC 8212 parity)** — **Done (2026-06-12).** `import_policies_v6:
  HashMap<Ipv4Addr, Policy<Route<Ipv6Addr>>>` added to `DaemonState`, initialized with the
  same `DefaultAction` as `import_policies` (Reject for eBGP, Accept for iBGP per RFC 8212).
  `handle_update` applies BLACKHOLE check + `policy_v6.evaluate()` to all IPv6 announcements.
  Test: `test_rfc8212_ebgp_ipv6_reject_without_policy` verifies eBGP routes are rejected and
  stored in AdjRibIn for soft-reconfig.

- **Panic safety in main event loop — Done.** All `expect()` calls in `run()` replaced with
  `let...else` + `tracing::error!` + `continue`. Unknown peer IPs now log an error and skip
  the event rather than panicking the daemon.

- **Soft reconfiguration → export propagation — Done (2026-06-09).** `set_import_default` and `set_export_default` on `DaemonState` call `reapply_import_policy` and then immediately call `propagate_prefix` for every affected NLRI to all established peers. Exposed via `PolicyService` gRPC; `pathvector policy set-import/set-export` CLI subcommands wrap it. Two e2e tests confirm the full chain.

- **Advertise `MultiProtocol(IPv4_UNICAST)` capability** — pathvectord currently only
  advertises `Capability::FourByteAsn`. RFC 4760 requires speakers that support
  MP_REACH_NLRI / MP_UNREACH_NLRI for an AFI/SAFI to advertise the corresponding
  `MultiProtocol` capability in their OPEN. Without it, well-behaved peers (including
  newer GoBGP versions) will use traditional NLRI format rather than MP_REACH_NLRI,
  which means the `handle_update` MP code path — though implemented and unit-tested —
  has never run against a real peer. Adding `Capability::MultiProtocol(AfiSafi::IPV4_UNICAST)`
  to the session config:
  - Brings the implementation into RFC 4760 compliance
  - Causes GoBGP to send IPv4 routes via MP_REACH_NLRI, exercising the MP code path e2e
  - Is the prerequisite step for advertising IPv6 capability later

  One-line change in `pathvectord/src/main.rs` where capabilities are constructed;
  the codec already encodes/decodes the capability correctly.

- IPv6 in the daemon — the session layer already speaks IPv6 via MP_REACH_NLRI, but
  `pathvectord` is hardcoded to `Route<Ipv4Addr>`. Extending to IPv6 requires a
  dual-stack RIB or a generic event dispatch on address family.
  **IPv4 MP path done (2026-06-08):** `handle_update` now processes `MP_UNREACH_NLRI`
  and `MP_REACH_NLRI` attributes for AFI/SAFI=IPv4 unicast. Peers that send IPv4
  withdrawals or announcements via the multiprotocol attributes instead of the
  traditional fields are handled correctly. Non-IPv4 AFI/SAFIs are logged at DEBUG
  and skipped. Full IPv6 RIB support still requires the dual-stack work above.

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

- gRPC management API — **Done (2026-06-09).** `PeerService`, `RibService`, and `PolicyService` are live. Proto schema at `proto/pathvector/v1/management.proto`. See [DAEMON.md](DAEMON.md) for the full operational guide and `grpcurl` examples; see [CLI.md](CLI.md) for the `pathvector` CLI reference.
- gRPC server reflection — **Done (2026-06-08).** `tonic-reflection` registered at startup. `grpcurl` now works without `--proto` flags; `grpcurl -plaintext localhost:50051 list` discovers all services at runtime.
- Import policy — **Done.** `handle_update` now evaluates a `Policy<Route<Ipv4Addr>>` per route before `LocRib::insert`; routes that return `Reject` are dropped. Per-peer default action (`import_default = "accept"` / `"reject"`) is configurable in TOML; eBGP peers default to `"reject"` (RFC 8212) when omitted, iBGP peers default to `"accept"`. The infrastructure is in place for adding `Term` conditions (prefix lists, community filters, etc.).
- **RFC 8654 Extended Message — Done (2026-06-10).** `BgpCodec` is now stateful; `set_extended_message(true)` raises the frame limit to 65535 bytes after both peers negotiate `Capability::ExtendedMessage` (code 6). `MAX_LEN`/`MAX_LEN_EXTENDED` are the single source of truth shared between the framing and message layers. `BgpMessage::decode_with_limit` added for explicit limit control. Two proptests cover large-message roundtrip and rejection without negotiation. The transport `execute` loop calls `set_extended_message` in the `SessionEstablished` arm.
- **RFC 6286 AS-wide unique BGP ID — Done (2026-06-10).** `validate_open` rejects iBGP peers that present the same BGP ID as the local speaker with `NOTIFICATION(BadBgpIdentifier)`; eBGP peers are exempt per the RFC. Two unit tests cover the accept/reject paths.
- **RFC 5492 Unsupported Capability — Done (2026-06-10).** `required_capabilities: Vec<Capability>` added to `FsmConfig`/`SessionConfig`. `validate_open` emits `NOTIFICATION(UnsupportedCapability)` with capability codes encoded in the data field when a required capability is absent. Retry after stripping rejected capabilities is deferred.
- **BLACKHOLE community discard action (RFC 7999) — Done (2026-06-10).** `handle_update` now checks `raw.communities.iter().any(|c| c.is_blackhole())` before the import-policy step. BLACKHOLE-tagged routes are stored in `AdjRibIn` (soft-reconfig visibility) but never installed in `LocRib` or advertised outbound. Three unit tests cover: not-installed, stored-in-AdjRibIn, and non-BLACKHOLE routes unaffected.
- `AdjRibIn` — **Done.** Per-peer `AdjRibIn` tables are built at startup and wired through `handle_update`. Raw (pre-policy) routes are stored on every announcement; withdrawals remove from both `AdjRibIn` and `LocRib`; session teardown calls `AdjRibIn::clear()`. `reapply_import_policy` re-evaluates all stored raw routes against a new policy, inserting accepted routes and withdrawing rejected ones from `LocRib` without a session reset.
- **CLI binary (`pathvector`) — Done (2026-06-09).** `peer list/get`, `route list/best/candidates`, `policy set-import/set-export`, and `dashboard` (live ratatui TUI). See [CLI.md](CLI.md).
- **Docker image** — **Done (2026-06-09).** `e2e/Dockerfile.pathvectord` is a multi-stage build:
  `rust:1.88-slim-bookworm` builder (with `protobuf-compiler`), `debian:bookworm-slim` runtime
  (with `netcat-openbsd` for HEALTHCHECK). Config file is bind-mounted at container start.
  gRPC port 51200 is exposed and mapped dynamically by testcontainers. Built via `just e2e-images`.

---

## pathvector-client

**Done (2026-06-08).** Self-contained gRPC client library for the `pathvectord`
management API. No dependency on any internal `pathvector-*` crate — all domain
types are defined independently in `src/types.rs`.

### Done

- `PathvectorClient::connect(addr)` — lazy channel construction; no async required
- `list_peers()`, `get_peer(addr)` — full `PeerState` conversion from proto
- `get_best_route(prefix)` → `Option<Route>`, `list_routes(peer_filter)`, `list_candidates(prefix)`
- `TryFrom` conversion layer (`src/convert.rs`) with explicit error variants:
  `InvalidAddress`, `UnknownEnumValue`, `BadExtendedCommunityLen`
- Three error types: `ConnectError`, `ClientError`, `ConvertError` — all with
  `Display`, `Error::source`, and `From` impls; no `thiserror`
- Optional `serde` feature flag on all domain types
- **Route origination API (2026-06-10):** `originate_route`, `originate_routes`,
  `withdraw_originated_route`, `withdraw_originated_routes`, `list_originated_routes`
  added to `DaemonClient` trait and implemented on `PathvectorClient`.
  `OriginateRouteParams` domain type in `types.rs`; `From` impl in `convert.rs`.
- **Streaming watch RPCs (2026-06-10):** `watch_routes(peer: Option<&str>)` and
  `watch_peers()` as inherent methods on `PathvectorClient`; return
  `impl Stream<Item = Result<RouteEvent/PeerEvent, ClientError>>`.  Not included
  in `DaemonClient` trait (stream types are too complex to mock generically).
  `RouteEvent`, `RouteEventType`, `PeerEvent`, `PeerEventType` domain types added.
- **`Route.peer_address: Option<IpAddr>` (2026-06-10):** Changed from `IpAddr`
  to `Option<IpAddr>`; `None` means locally originated route.  `convert.rs` maps
  proto `"local"` string → `None`; output rendering shows `"local"` for CLI/dashboard.
- **Test coverage 97%+ workspace-wide (2026-06-10):** Comprehensive unit and
  integration tests added across all crates. Key gaps closed: grpc origination
  handlers, watch stream deadlock fix (drop sender before polling), lib.rs watch
  conversion closures, transport retry/ExtendedMessage/MpReachNlri paths. All
  clippy `-D warnings` errors resolved.

### Remaining

- `serde` feature: `Serialize`/`Deserialize` derives are gated but not yet
  implemented on the domain types (blocked on deciding JSON schema conventions)
- Policy introspection RPC (`ListTerms`, `EvalRoute`) — blocked on
  `reapply_import_policy` being wired to export propagation in `pathvectord`

### Route origination API + gRPC streaming watch RPCs — **Done (2026-06-10)**

`OriginationService` is live on `pathvectord` with five RPCs: `OriginateRoute`,
`OriginateRoutes` (batch), `WithdrawOriginatedRoute`, `WithdrawOriginatedRoutes` (batch),
and `ListOriginatedRoutes`.  Routes are injected directly into `LocRib` under the synthetic
`LOCAL_ORIGIN_PEER` (`0.0.0.0`) key, bypassing import policy; export policy still applies
per peer.  A single `propagate_to_all_peers` call after the batch completes means N routes
produce ~2 BGP UPDATE messages per peer regardless of N.

`WatchRoutes` and `WatchPeers` streaming RPCs are live on `RibService` and `PeerService`.
Snapshot-then-stream: subscribe to broadcast channel first (no race), send current state as
`CURRENT` events, send `END_INITIAL` sentinel, then stream live deltas.  `broadcast::channel`
capacity 1024; slow subscribers receive `RecvError::Lagged` and must reconnect.

`pathvector-client` exposes the full origination and watch surface on `DaemonClient` trait
and `PathvectorClient` impl. `watch_routes` and `watch_peers` are methods on the
`DaemonClient` trait returning `BoxStream<T>` — a `Pin<Box<dyn Stream<...> + Send>>` type
alias that is nameable in struct fields, variable bindings, and `dyn` contexts.
`OriginateRouteParams`, `RouteEvent`, `PeerEvent`, `RouteEventType`, `PeerEventType` domain
types added to `types.rs`; `From`/`TryFrom` impls in `convert.rs`.

CLI subcommands `route originate`, `route withdraw`, `route list-originated`, `watch routes
[--peer]`, and `watch peers` all wired and tested (2026-06-10).

e2e test suite added (2026-06-11): 12 tests in `e2e/tests/origination.rs` covering
originated route propagation to GoBGP, batch origination, withdrawal, idempotent
re-origination, attribute preservation (communities, local_pref, med), blackhole community
(RFC 7999), coexistence with peer-learned routes, and no-op withdrawal of unknown prefix.

**Dashboard streaming done** — see Tier 2, item 5 above.

---

## Cross-cutting

### Design patterns / dependency-inversion improvements

Three targeted changes that improve testability or robustness without over-engineering.
Priority order matches the payoff-to-cost ratio.

1. **`RibSnapshot` split** — see Performance item 5 above; listed there because it is
   primarily a performance fix, but it also decouples gRPC reads from the event loop entirely,
   which is an architectural improvement in its own right.

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

3. **`RibView` trait for `propagate_prefix`** (`pathvectord`) — `propagate_prefix` currently
   takes `&LocRib<Ipv4Addr>` directly. A narrow `RibView` trait (just `best(&Nlri) ->
   Option<&Route>`) would make the function unit-testable with a trivial stub instead of
   requiring a fully populated `LocRib`. Useful before best-path selection grows more
   complex (ECMP, route reflector client preference, etc.). Defer until then.

### Architecture overview document

**Done (2026-06-09).** `ARCHITECTURE.md` at the workspace root covers:
- Crate dependency graph with rationale for `pathvector-client` having no internal deps
- Full inbound route path: TCP socket → codec → FSM → SessionEvent → DaemonState →
  AdjRibIn → import policy → LocRib
- Full outbound route path: LocRib best-path change → propagate_prefix → export policy →
  AdjRibOut → outbound UPDATE channel → Session → TCP socket
- Session lifecycle events table (Established / Terminated / RouteUpdate)
- Management plane: Arc<RwLock<DaemonState>>, read/write lock split rationale
- BgpTransport trait seam and how spawn_with injects a mock transport in tests
- DaemonState owns no I/O — all side effects flow through mpsc channels
- Key design invariants (pure FSM, zero-dep types, idempotent propagate_prefix, etc.)

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

- CI pipeline: `cargo test`, `cargo clippy`, `cargo doc`, MSRV check (1.88) — **Done.** `.github/workflows/ci.yml` has five jobs: `test` (stable), `lint` (clippy + rustfmt, stable), `msrv` (1.88), `docs` (stable, `-D warnings`), and `fuzz` (nightly, `just fuzz-smoke`). A `Justfile` at the workspace root provides matching local recipes so CI and development use the same commands. All jobs install `protoc` (required by `pathvectord`'s gRPC codegen build script).
- Integration test isolation — `tests/transport.rs` binds real loopback TCP sockets; these tests are excellent for correctness but will be slow and port-conflict-prone on shared CI runners; consider a `#[cfg(not(ci))]` guard or dedicated test binary with a randomised port range
- Fuzz testing — tracked as Phase 4 in the property testing section above

### Performance

#### Known architectural concerns

These are structural decisions in the current implementation worth measuring before
deciding whether to address them. All are acceptable at small peer counts and RIB
sizes; they become bottlenecks at internet scale (tens of peers, ~950k IPv4 prefixes).

1. ~~**`try_send` failure on the outbound UPDATE channel**~~ — **Fixed (2026-06-09).**
   `propagate_prefix` now returns `bool`; a `false` return means the channel was full.
   The three `DaemonState` event methods collect stalled peers into `self.stalled_peers`.
   After each event, `run()` sends `SessionCommand::Stop` to each stalled session via a
   retained `stop_senders` map (populated from a new `SessionHandle::stop_sender()`
   method). The session re-establishes and `on_established` performs a fresh full-table
   dump from a clean `AdjRibOut`, restoring a consistent peer view. Overflow is logged
   at `ERROR`. Tests updated from "does not panic" to "returns false" assertions.

2. **Single event loop for all peers** — all peer sessions funnel into one `mpsc` channel;
   `DaemonState` processes events sequentially under a write lock. A large UPDATE from one
   peer (e.g., a full-table session establishment) blocks event processing for every other
   peer for the duration, creating hold-timer pressure at high peer counts. Sharding
   `DaemonState` by address family or introducing a per-peer processing pipeline would fix
   this, but requires significant ownership rework.

3. **No NLRI batching in outbound UPDATEs** — each affected prefix generates its own
   `UpdateMessage` and wire frame. RFC 4271 allows packing multiple NLRIs with identical
   path attributes into a single UPDATE. Batching reduces TCP segment count and framing
   overhead, which matters most during full-table dumps to newly established peers.

4. **Full-table dump on peer establishment holds the write lock** — `on_established`
   iterates the entire `LocRib` and calls `propagate_prefix` for every best route before
   releasing the write lock. At ~950k routes this is a multi-millisecond stall that blocks
   both the BGP event loop and all concurrent gRPC reads. Fix: generate the dump
   asynchronously, releasing the lock between batches.

5. ~~**`RibSnapshot` split — eliminate gRPC/event-loop read contention**~~ — **Done (2026-06-11).**
   `DaemonState` now holds `rib: Arc<RibSnapshot>`. gRPC handlers call `snapshot()` to clone
   the `Arc` (O(1) atomic increment) and release the outer lock before iterating. The event
   loop mutates via `Arc::make_mut` — zero-cost when refcount is 1, copy-on-write only when
   a gRPC call is in-flight. See `DECISIONS.md` for full rationale.

   **Known concern — CoW under long-lived gRPC streams**: `Arc::make_mut` is zero-cost
   when refcount == 1 (no management-plane reader in flight — the common case). The O(N)
   clone only fires when a snapshot `Arc` is held *while* the event loop mutates state.
   Point-in-time calls (`ListRoutes`, `GetBestRoute`) release the snapshot immediately so
   contention is microsecond-scale. The risk is a future long-lived streaming handler
   (e.g. `WatchRoutes`) retaining a snapshot Arc across yield points — that would make
   every UPDATE during the stream's lifetime a full RIB clone.

   **Why `arc-swap` is not the right fix**: `arc-swap` requires cloning the full snapshot
   on *every* write (clone → mutate → swap), making BGP UPDATE processing always O(N).
   `Arc::make_mut` is O(1) in the common case and only pays the clone cost on actual
   contention — strictly better for a write-heavy event loop with rare management reads.

   **Correct mitigation**: ensure streaming handlers never hold a snapshot `Arc` across
   `await` points. Each streamed event should carry its own data (already the case for
   watch handlers via the broadcast channel). Audit any new streaming RPC before merging
   to confirm it drops the snapshot before its first yield.

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
- NLRI batching (concern #3 above) should be addressed first so outbound performance
  is not artificially penalised
- The full-table dump lock-hold (concern #4) should be measured separately from the
  inbound convergence benchmark
- A RouteViews MRT dump needs to be converted to ExaBGP's `announce` format (the
  `exabgp-mrt` tool does this); the converted file should be committed to `bench/fixtures/`
  (or downloaded by the benchmark harness to avoid repo bloat)

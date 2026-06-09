# TODO

Tracked items that are intentionally deferred — known gaps, planned features,
and protocol steps that require components not yet built. Each entry notes
which crate it belongs to and why it was deferred.

---

## Prioritized next steps

Items are grouped by what they unlock, not just by effort. A small correctness
fix that unblocks a larger feature is worth doing before the feature itself.

### Tier 1 — Small scope, high correctness or coverage value

**1. Advertise `MultiProtocol(IPv4_UNICAST)` capability** (`pathvectord`)
One line in the session config construction. Brings the OPEN into RFC 4760
compliance and causes GoBGP to send IPv4 routes via MP_REACH_NLRI — the first
time the MP code path runs against a real peer. Also the mandatory first step
before advertising IPv6 capability. Low risk, immediate coverage gain.

**2. Wire `reapply_import_policy` → export propagation** (`pathvectord`)
Currently policy reloads update the Loc-RIB but do not trigger outbound
UPDATEs to peers. This is a silent correctness hole: after a policy change,
peers continue to receive routes based on the old policy until they reconnect.
Fixing it unblocks the gRPC policy introspection RPC and completes the
import-policy story that RFC 8212 e2e tests already exercise on the inbound
side.

### Tier 2 — Medium scope, architectural or user-facing value

**3. RFC 7606 revised UPDATE error handling** (`pathvector-session`, `pathvectord`)
Currently every malformed attribute resets the session. RFC 7606 requires
per-attribute error policies (session reset / treat-as-withdraw / attribute
discard). This is architectural — it touches the codec, transport layer, and
daemon event loop — and gets harder to retrofit as the codebase grows. Doing
it now means every future attribute decode arm gets the correct error policy
for free. See the dedicated section below.

**4. CLI tool (`pathvector`)** (new crate, uses `pathvector-client`)
The management API exists and `pathvector-client` wraps it cleanly. A CLI is
the lowest-friction way for an operator (or a developer evaluating the project)
to inspect peers and routes without writing Rust or using grpcurl. Commands:
`peer list`, `peer get <addr>`, `route get <prefix>`, `route list`. Straightforward
to implement; high value for the "would I use this?" question.

**5. IPv6 RIB — inbound half** (`pathvectord`)
After item 1 (MultiProtocol capability) is done, advertising IPv6 capability
becomes a matter of adding parallel `LocRib<Ipv6Addr>` / `AdjRibIn<Ipv6Addr>`
tables to `DaemonState` and routing `AfiSafi::IPV6_UNICAST` events to them.
The RIB library is already generic. The outbound half (constructing MP_REACH_NLRI
UPDATE messages with a valid IPv6 next-hop) is harder and can follow separately.

### Tier 3 — Larger scope, important but not blocking

**6. BIRD interoperability**
BIRD is stricter than GoBGP about RFC compliance. Running the existing e2e suite
against BIRD would surface any GoBGP-specific leniency the implementation
currently relies on. Mostly infrastructure work (Dockerfile.bird, bird.conf).

**7. Criterion benchmark suite**
Per-crate benchmarks with the three-size pattern (small/medium/large).
Establishes the baseline before performance optimisations. Described in detail
under Cross-cutting → Performance below.

**8. Adversarial input / NOTIFICATION path testing**
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
- Adversarial inputs — malformed BGP messages injected directly over TCP to verify the
  daemon handles them gracefully without panicking
- **GitHub Actions e2e workflow** — **Done (2026-06-09).** Separate `e2e` job in
  `.github/workflows/ci.yml` on `ubuntu-latest` (Docker pre-installed). Uses
  `docker/setup-buildx-action` + `docker/build-push-action` with `type=gha` layer
  caching (separate scopes for `gobgpd` and `pathvectord` images). GoBGP image is a
  cache hit on repeat runs. `test` and `msrv` jobs now pass `--exclude pathvector-e2e`
  so the crate is not exercised without its required images. A `.githooks/pre-push` hook
  (installed via `just install-hooks`) runs `just e2e` locally before each push.
- **BIRD interoperability** — add a second peer implementation. BIRD is stricter about RFC
  compliance than GoBGP (it's the reference implementation for many IXP route servers) and
  will catch things GoBGP tolerates. A `e2e/Dockerfile.bird` wrapping the official BIRD
  package + `e2e/fixtures/bird.conf` is all that's needed; the `Harness` architecture already
  supports multiple peer images. Target: run the same 10 session + route tests against BIRD
  to confirm the handshake and UPDATE exchange is broadly interoperable, not just GoBGP-specific.

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

- **Panic safety in main event loop — Done.** All `expect()` calls in `run()` replaced with
  `let...else` + `tracing::error!` + `continue`. Unknown peer IPs now log an error and skip
  the event rather than panicking the daemon.

- Soft reconfiguration → export propagation — `reapply_import_policy` changes which routes
  are in `LocRib`, but does not currently trigger `propagate_prefix` to update peers. Callers
  that perform policy reloads must trigger outbound propagation manually until this is wired.

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

- gRPC management API — **Done (2026-06-08).** `PeerService` and `RibService` are live on a configurable port (default 50051). Proto schema at `proto/pathvector/v1/management.proto`. See [DAEMON.md](DAEMON.md) for the full operational guide and `grpcurl` query examples. Remaining: policy introspection and runtime policy reload (blocked on wiring `reapply_import_policy` to export propagation).
- gRPC server reflection — **Done (2026-06-08).** `tonic-reflection` registered at startup. `grpcurl` now works without `--proto` flags; `grpcurl -plaintext localhost:50051 list` discovers all services at runtime.
- Import policy — **Done.** `handle_update` now evaluates a `Policy<Route<Ipv4Addr>>` per route before `LocRib::insert`; routes that return `Reject` are dropped. Per-peer default action (`import_default = "accept"` / `"reject"`) is configurable in TOML; eBGP peers default to `"reject"` (RFC 8212) when omitted, iBGP peers default to `"accept"`. The infrastructure is in place for adding `Term` conditions (prefix lists, community filters, etc.).
- BLACKHOLE community discard action (RFC 7999) — `Community::BLACKHOLE` (0xFFFF029A) is defined and detectable via `is_blackhole()`, but there is no null-route or discard action wired in the RIB or daemon; routes tagged with BLACKHOLE should have traffic to their prefix dropped at the forwarding plane
- `AdjRibIn` — **Done.** Per-peer `AdjRibIn` tables are built at startup and wired through `handle_update`. Raw (pre-policy) routes are stored on every announcement; withdrawals remove from both `AdjRibIn` and `LocRib`; session teardown calls `AdjRibIn::clear()`. `reapply_import_policy` re-evaluates all stored raw routes against a new policy, inserting accepted routes and withdrawing rejected ones from `LocRib` without a session reset.
- CLI binary (`pathvector`) using the gRPC client
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
- 83 unit tests (including 10 proptest properties) + 12 integration tests driven
  by an in-process mock gRPC server; all pass under `just ci` (MSRV 1.88)
- Optional `serde` feature flag on all domain types

### Remaining

- `serde` feature: `Serialize`/`Deserialize` derives are gated but not yet
  implemented on the domain types (blocked on deciding JSON schema conventions)
- Policy introspection RPC (`ListTerms`, `EvalRoute`) — blocked on
  `reapply_import_policy` being wired to export propagation in `pathvectord`

### gRPC streaming watch RPCs

The current management API is purely request/response — operators and tests must poll to
observe changes. Adding server-side streaming RPCs would make the API event-driven:

```protobuf
rpc WatchRoutes(WatchRoutesRequest) returns (stream RouteEvent);
rpc WatchPeers(WatchPeersRequest)  returns (stream PeerEvent);
```

Where `RouteEvent` carries `oneof { Route announced = 1; string withdrawn_prefix = 2; }`
and `PeerEvent` carries the updated `PeerState`.

Benefits:
- **e2e tests** — replace `wait_for_route` polling loops with an event-driven subscription;
  tests become faster and have no arbitrary sleep timeouts
- **CLI** — `pathvector watch routes` / `pathvector watch peers` become natural commands
- **Operators** — live monitoring without external polling scripts

Implementation touches: proto schema, daemon event fan-out (the session event channel
already carries all the information — each watch stream registers as a receiver), and the
client library (`watch_routes() -> impl Stream<Item = RouteEvent>`). The daemon side
requires careful backpressure handling: a slow watch client must not block the main loop.
Consider a bounded broadcast channel per watch stream with the oldest entry dropped on
overflow (same pattern as Tokio's `broadcast::channel`).

---

## Cross-cutting

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

# Changelog

All completed implementation items, extracted from TODO.md and organized by completion date.

---

## 2026-06-18 (continued)

### [pathvector-session / pathvectord] Per-peer hold timer, RFC 9003 shutdown message, RFC 7313 codec, ROUTE-REFRESH trigger

Four small-to-medium protocol features added across `pathvector-session` and `pathvectord`.

**Per-peer hold timer** — `PeerConfig.hold_time: Option<u16>` added. `build_daemon` and the `AddPeer`
command processor fall back to `DaemonConfig.hold_time` when the per-peer value is absent, preserving
existing behaviour for all peers that do not override it.

**RFC 9003 — Extended admin shutdown communication** — `encode_shutdown_message` /
`decode_shutdown_message` added to `pathvector-session::message::notification`. Wire format: 1-byte
length prefix + UTF-8 string, max 128 bytes, in the CEASE NOTIFICATION `data` field. `pathvectord`
reads `shutdown_message: Option<String>` from `PeerConfig`; `RemovePeer` sends
`Cease/AdministrativeShutdown` with the encoded payload instead of a bare `Stop` command when a
reason is configured. 6 new unit tests (round-trip, truncation, empty-data, length-overrun,
NOTIFICATION integration).

**RFC 7313 — Enhanced Route Refresh codec** — `RouteRefreshSubtype` enum added to
`pathvector-session::message::route_refresh`. The previously reserved byte in the 4-byte ROUTE-REFRESH
wire format is now decoded as `Refresh` (0), `BeginRefresh` (1), `EndRefresh` (2), or `Unknown(u8)`.
`RouteRefreshMessage::new(afi_safi)` constructor added (subtype defaults to `Refresh`). Encode/decode
updated; all existing callers migrated; 4 new codec tests added.

**Outbound ROUTE-REFRESH trigger / `SoftReset` gRPC RPC** — `SessionCommand::RouteRefresh(RouteRefreshMessage)`
variant added to `pathvector-session::transport`. `SessionHandle::send_route_refresh` trait method
wired through `SpawnedSessionHandle` → command channel → session actor. `SoftReset` RPC added to
`PeerService` proto; `PeerServiceImpl::soft_reset` resolves the peer's session actor by IP, parses the
AFI/SAFI from the request, and sends a `RouteRefresh` command. `pathvector-client/tests/integration.rs`
updated with the new trait method on all mock implementations.

### [pathvectord] Dynamic peer loose-end fixes — broadcast safety, race-safety tests, restart persistence

Three correctness and operational gaps closed after the initial audit pass.

**`peer_tx` broadcast capacity comment:** Added an inline comment at the
`broadcast::channel(1024)` creation site explaining the bounded capacity,
`RecvError::Lagged` behavior, and the self-healing guarantee: the `watch_peers`
stream handler re-reads the full peer snapshot on any `Changed(peer: None)` signal,
so a lagging receiver catches up without permanent event loss.

**`incoming_senders` race-safety tests (2 new unit tests):**
- `remove_peer_clears_incoming_senders` — drives `RemovePeer` through the real
  `run_command_processor` and asserts the peer's entry is gone from `incoming_senders`
  before `Terminated` fires, proving the reconnect race window is closed at the
  command-handler level.
- `bgp_listener_drops_unlisted_peer` — starts the real TCP listener with an empty
  `incoming_senders` map, connects via loopback, and asserts EOF — the connection is
  RST'd immediately with no data sent.

**Restart persistence — `DynamicPeerStore` (6 unit tests + 2 integration tests):**
`config::DynamicPeerStore` writes a TOML sidecar (`dynamic_peers.toml`, same directory
as the static config) on every `add_peer` and `remove_peer` using atomic
write-then-rename. `main.rs` loads the sidecar at startup, merges its peers into
`cfg.peers` (skipping any address already in the static config), and passes the sidecar
path into `run_command_processor` for write-through. Six unit tests cover: load-absent
returns empty, upsert persists, upsert is idempotent by address, remove deletes,
remove-unknown is a no-op, full-field round-trip. Two `run_with_tests` integration
tests prove the restart path: sidecar peer gets a spawned session; static-config
duplicate is not spawned twice.

### [pathvector-rib] Criterion benchmark baseline — M2 Max

Three benchmark targets added to `pathvector-rib/benches/`, establishing the
performance baseline for the RIB and outbound pipeline on Apple M2 Max, 96 GB RAM.

**`select_best`** — RFC 4271 §9.1 best-path decision across N candidates:
- 2 candidates: **158 ns** (typical iBGP mesh)
- 10 candidates: **504 ns** (realistic eBGP fan-out)
- 100 candidates: **2.6 µs** (pathological; O(N) as expected)

**`loc_rib_insert`** — one insert into a pre-populated RIB triggering best-path
recompute:
- 10k prefixes: **614 ns** (full internet table range)
- 100k prefixes: **582 ns** (flat — HashMap lookup dominates, not table size)
- 500k prefixes: **2.1 µs** (mild L3 cache pressure; still sub-3 µs)

**`outbound_pipeline`** — `prepare_outbound` + `AdjRibOut::insert` per peer for
one prefix change, measured for minimal (2-hop path, no communities) and dense
(15-hop, 8 communities) routes:
- minimal/1 peer: **313 ns** | minimal/10: **1.4 µs** | minimal/50: **6.8 µs**
- dense/1 peer: **468 ns** | dense/10: **2.8 µs** | dense/50: **13.7 µs**

Per-peer amortised cost is constant (~136 ns/peer minimal, ~274 ns/peer dense);
community vec allocation accounts for the ~2× dense overhead.

---

## 2026-06-18

### [pathvectord, pathvector-client, pathvector] Dynamic peer robustness — correctness audit fixes

Six issues identified in a post-implementation audit of the `AddPeer`/`RemovePeer`
feature. All protocol-observable issues are resolved; two operational limitations
remain documented in `pathvectord/README.md`.

**`FAILED_PRECONDITION` guard for mid-teardown AddPeer (gap 1):** `grpc.rs` `add_peer`
handler now reads `pending_removal` before sending the `DaemonCommand`. Returns
`FAILED_PRECONDITION("peer removal in progress; retry after peer disappears from
list_peers")` rather than returning `OK` for an add that will be silently dropped.
The command processor also logs `warn!` and drops the add if the race is lost after
the pre-check passes.

**Correct `Removed` events on `WatchPeers` (gap 4):** Previously, `watch_peers`
subscribers received `Removed` events with zeroed `remote_as`/`local_as` because the
peer state was already erased before the stream handler could read it. Fixed by
capturing `remote_as` and `local_as` from the RIB *before* `on_terminated` and
`remove_peer` run, then broadcasting an explicit `proto::PeerEvent { type: Removed,
peer: Some(PeerState { address, remote_as, local_as, .. }) }` directly from the event
loop. `on_terminated` now accepts a `notify: bool` parameter — it suppresses its
intermediate `Changed(None)` broadcast during removal so the stream receives exactly
one `Removed` event, not a `Changed` followed by a `Removed`. The stream handler
forwards explicit `Removed` events directly rather than re-deriving them via snapshot
diffing. `dashboard.rs` `apply_peer_event` handles `Removed` with `retain`. Three new
unit tests cover `Removed`/partial-removal/unknown-address-no-op cases.

**Propagation stall observability (gap 5):** `on_terminated`'s re-propagation loop
now wraps its body with `Instant::now()` and emits `tracing::warn!` if the loop holds
the state write lock for more than 100 ms, including peer address, prefix count, and
elapsed milliseconds. Operators can now detect large-table removal stalls in production
before they cause cascading hold-timer failures.

**Command processor panic watchdog (gap 6):** `run()` now wraps the
`run_command_processor` join handle in a second `tokio::spawn` that logs
`tracing::error!` if the task exits with a panic, making the failure visible in
structured logs rather than silently breaking `AddPeer`/`RemovePeer`.

**`DynamicPeerHarness` + `wait_for_peer_absent` (gap 4 verification):** New e2e test
harness starts `pathvectord` with zero static peers. Four e2e tests: dynamic add
establishes session, idempotent add is a no-op, remove withdraws routes and removes
peer, add/remove cycle. `wait_for_peer_absent` polls `list_peers` until the target IP
disappears.

**Remaining open gaps:** dynamic peers don't survive daemon restart (gap 2); MD5
passwords on dynamically-added peers don't protect inbound connections because the
listener socket is bound once at startup (gap 3). Both are documented in
`pathvectord/README.md`.

---

## 2026-06-17

### [pathvectord, pathvector-client] Dynamic peer reconfiguration — AddPeer / RemovePeer gRPC RPCs

Runtime peer management without daemon restart. Operators can now add and remove BGP
peers over the gRPC management API while other sessions remain unaffected.

**Proto:** `AddPeer` and `RemovePeer` RPCs on `PeerService`; `AddPeerRequest` carries
address, remote AS, port, import/export default policy (`PolicyAction`), and optional
RFC 2385 MD5 password. AS 0 and AS 23456 (AS_TRANS, RFC 7607) rejected with
`INVALID_ARGUMENT`.

**Architecture:** `DaemonCommand` enum bridges the gRPC layer to the event loop without
leaking generics. A separate `run_command_processor` task handles commands so the event
loop signature stays stable. `incoming_senders` and `md5_passwords` are
`Arc<RwLock<HashMap>>` so the BGP listener picks up newly added peers immediately.
`stop_senders` is `Arc<Mutex<HashMap>>` with a lock-clone-await pattern so the sender
is never held across an `await`.

**Teardown sequencing:** `pending_removal: HashSet<Ipv4Addr>` in `DaemonState` signals
the `Terminated` handler to run a full state purge (`remove_peer` — clears all
per-peer RIB/policy maps) instead of a reconnect-ready reset (`on_terminated`). This
guarantees routes are withdrawn from the Loc-RIB before peer state is destroyed.

**Liveness fix:** if the session actor has already exited between reconnects (stop sender
dropped), the command processor synthesizes `SessionEvent::Terminated` directly via
`event_tx` so the `pending_removal` cleanup still runs.

**`AddPeer` is idempotent** — re-adding an existing peer is a no-op. `RemovePeer` on
an unknown peer returns `NOT_FOUND`.

**Client:** `AddPeerParams` type + `add_peer` / `remove_peer` on the `DaemonClient`
trait; `PathvectorClient` implementation; `MockDaemonClient` stubs.

Tests added: `add_peer_inserts_all_state_maps`, `add_peer_is_idempotent`,
`remove_peer_clears_all_state_maps`, `remove_peer_returns_false_when_not_found`,
`terminated_with_pending_removal_calls_remove_peer`,
`terminated_without_pending_removal_keeps_peer_state`,
`remove_peer_synthesizes_terminated_when_no_stop_sender`,
`test_add_peer_invalid_address`, `test_add_peer_rejects_as_zero`,
`test_add_peer_rejects_as_trans`, `test_add_peer_sends_command_on_valid_request`,
`test_remove_peer_invalid_address`, `test_remove_peer_not_found`,
`test_remove_peer_sends_command_when_peer_exists`.

### [pathvector-rib] RFC-correct same-AS MED comparison in best-path selection

RFC 4271 §9.1.2.2 requires MED to be compared only between routes from the same neighboring
AS. The prior implementation compared MED globally, and a partial pairwise fix was
non-transitive for 3+ routes across multiple ASes — `max_by` produces unspecified results on
a non-total order.

Correct algorithm (`select_best_with_oracle`):
1. Group candidates by `AsPath::neighboring_as()` (first ASN in first Sequence segment).
2. Select the best within each group — all routes share the same `neighboring_as()`, so
   `prefer()` applies MED correctly.
3. Compare group winners — different neighboring ASes, so `prefer()` skips MED, guaranteeing
   a total order.

`AsPath::neighboring_as()` added to `pathvector-types`. Tests: `test_med_ignored_for_different_neighboring_as`,
`test_med_compared_within_same_neighboring_as`. Proptest: `prop_med_winner_is_insertion_order_independent`
tries all six insertion orders of a 3-route cross-AS scenario and verifies the same peer
wins every time — this test would have directly caught the non-transitivity bug.

### [pathvector-rib, pathvectord] RIB memory optimisation — 57% reduction at 500k routes

Six-commit series reducing per-route memory from ~2.6 KB to ~0.57 KB at 500k routes:

1. **`LocRib` structural rewrite** — `best: RouteMap<A, PeerId>` stores the winning peer ID
   only (route always accessible via candidates lookup); flat `CandidateMap` +
   `PeerIndex<SmallVec<[PeerId; 4]>>` eliminates ~320 B per-prefix nested HashMap
   allocation. 500k routes: 1.4 GB → 605 MB.

2. **`AsPath` interning via `Arc<AsPath>`** — routes from the same BGP UPDATE share one
   `Arc<AsPath>` allocation. `RouteBuilder::with_shared_as_path` used in the UPDATE decode
   loop. CoW via `Arc::make_mut` in `prepare_outbound` when eBGP prepend is needed.
   Saves 16 bytes/route struct layout (Vec 24 B → Arc 8 B).

3. **Rare attribute boxing** — 7 attributes present in <5% of routes (`communities`,
   `large_communities`, `extended_communities`, `cluster_list`, `atomic_aggregate`,
   `aggregator`, `originator_id`) moved behind `Option<Box<RareAttrs>>`. Absent fields cost
   8 bytes (null pointer) instead of 96+ bytes of empty Vecs. 500k: 605 MB → 481 MB.

4. **AHash, SmallVec, `u32` timestamp** — `AHashMap`/`AHashSet` replaces `std::HashMap` in
   `LocRib` (eliminates SipHash overhead on internal keys). `PeerIndex` inner collection
   changed to `SmallVec<[PeerId; 4]>` (up to 4 peers inline, no heap). `Route::received_at`
   shrunk from `Instant` (16 B) to `u32` Unix seconds (4 B), saving 12 B/route.

5. **Empty `AsPath` static intern** — `RouteBuilder::new` returns a clone of a
   process-wide `Arc<AsPath>` for empty paths (originated routes). Eliminates 500k ×
   40 B heap allocations at scale. 500k: 486 MB → 461 MB.

6. **Extended phases** — stress harness extended from 3 phases (10k/100k/500k) to 6
   (10k/100k/250k/500k/750k/900k). At 900k routes: pathvectord 515 MB vs GoBGP 792 MB
   (35% less); convergence 0.26 s vs 0.56 s (2.2× faster). Per-route cost: 0.57 KB
   (pathvectord) vs 0.88 KB (GoBGP).

### [pathvector-stress] GoBGP 1:1 synthetic benchmark harness

New `pathvector-stress` workspace crate runs both daemons on the same host with identical
workloads and prints side-by-side convergence time and peak RSS. GoBGP bench phase spawns
`gobgpd`, calls `StartBgp`, injects routes via `AddPathStream` gRPC, then reads RSS via
`ps`. `just stress` (debug) / `just stress-release` (optimised, numbers worth recording).
Includes `pathvector-stress/README.md` with prerequisites, port assignments, and baseline
numbers.

### [pathvector-mrt] MRT TABLE_DUMP_V2 replay against live pathvectord

New `pathvector-mrt` binary replays real internet routing table dumps:
- Parses MRT TABLE_DUMP_V2 format (RFC 6396); handles `.mrt` and `.mrt.gz` via `flate2`.
- Opens a real TCP BGP session to pathvectord (OPEN → KEEPALIVE → Established).
- Batches NLRIs with identical attribute bytes into single UPDATE messages up to the
  RFC 4271 4096-byte limit — matching real peer behaviour.
- Polls `watch_routes` gRPC stream until prefix count stabilises; reports convergence time
  and final RIB count. `list_all_routes` helper added to `DaemonClient` for paginated reads.
- Benchmark on M2 Max against RIPE RIS full table (1,133,510 IPv4 prefixes): 343,920
  prefixes/sec announcement throughput; 3.70 s RIB convergence; 7.00 s end-to-end.

`just mrt ./latest-bview.gz` recipe added. Parser and speaker have 7 unit tests.

### [pathvectord, pathvector-client] Cursor-based pagination for `ListRoutes`

`ListRoutesRequest` gains `page_size` and `page_token` fields. `page_size=0` (default)
returns all routes for backward compatibility; non-zero enables cursor-based pagination
sorted by prefix string. `DaemonClient::list_all_routes` issues paginated requests in a
loop (`PAGE_SIZE=5000`) to work around the 4 MB tonic limit. Test:
`test_list_routes_pagination_returns_all_routes_across_pages`.

### [pathvectord] gRPC correctness — `originate_route` validation and upsert semantics

`parse_originate_request` now rejects `next_hop = 0.0.0.0` with `INVALID_ARGUMENT` — an
unspecified address is never a valid BGP forwarding next-hop (RFC 4271 §5.1.3). Test:
`test_parse_originate_request_rejects_unspecified_next_hop`.

Upsert semantics documented in proto: re-originating the same prefix silently replaces the
previous route (HashMap::insert). Test: `test_originate_route_upsert_replaces_previous_route`.

### [pathvectord] Documentation — per-crate READMEs overhaul

Full documentation pass producing first-class per-crate READMEs for all 9 crates.
`pathvectord/README.md` absorbs `DAEMON.md` + `LOCAL_INTEROP.md` with field-by-field config
explanations and GoBGP/BIRD interop guide. Adds "Behavior on restart" section documenting
`RTPROT_BGP` stale-route cleanup. `docs/` mdBook and `CLI.md`, `DAEMON.md`, `PERFORMANCE.md`,
`LOCAL_INTEROP.md` removed; `book.toml` removed. `CONTRIBUTING.md` gains "Which crate do I
edit?" routing table. `e2e/` renamed to `pathvector-e2e/`, `fuzz/` to `pathvector-fuzz/`.

## 2026-06-16

### [pathvectord] RFC 4271 correctness audit — fixes (A, B, H, J)

**A — AS_PATH loop detection** (`pathvectord/src/daemon.rs`)
`handle_update` checks `as_path.contains(local_as)` and silently drops announcements
(not withdrawals), matching RFC 4271 §6.3 SHOULD. Tests: `test_as_path_loop_detection_*` (4 tests).

**B — Mandatory attribute presence** (`pathvectord/src/daemon.rs`)
`handle_update` now detects absent ORIGIN/AS_PATH/NEXT_HOP and returns a `NotificationMessage`
with `error = UpdateMessage(MissingWellKnownAttribute)` and `data = [attr_type]` (RFC 4271
§6.3 MUST). The full message is threaded through the event loop →
`SessionCommand::Notification` → FSM → wire. Tests: `missing_origin_returns_notification_*`,
`missing_as_path_returns_notification_*`, `missing_next_hop_*`,
`withdraw_only_update_no_notification_for_missing_attrs`,
`all_mandatory_attributes_present_no_notification`,
`malformed_update_missing_origin_sends_notification_to_session`.

**H — MRAI** (`pathvectord/src/daemon.rs`)
eBGP MRAI (30 s window) implemented via per-NLRI per-peer `mrai_last_sent` / `mrai_pending`
maps in `DaemonState`. Suppression converts `PrefixDecision::Announce` → `NoChange` after
`propagate_prefix` updates AdjRibOut (RIB is always correct; only wire transmission is
deferred). A half-MRAI flush timer calls `flush_mrai_pending` on elapsed NLRIs using
`partition()` — avoids the `max()` bug. Tests: `mrai_suppresses_ebgp_announcement_within_window`,
`mrai_passes_after_window_elapsed`, `has_mrai_pending_*` (2), `flush_mrai_pending_clears_elapsed_pending`,
`mrai_withdrawal_bypasses_suppression`. iBGP MRAI (RFC 4271 SHOULD ≥5 s) deferred.

**J — AS_TRANS / AS4_PATH for 2-byte-only peers (RFC 6793)** (`pathvectord/src/outbound.rs`)
`route_to_attributes` accepts `peer_four_byte: bool`. When `false`,
`AsPath::downgrade_for_two_byte_peer()` substitutes 4-byte ASNs with AS_TRANS (23456) in the
wire AS_PATH and appends AS4_PATH (type 17, flags 0xC0 optional+transitive) last per RFC 6793
§4. Tests: `two_byte_asns_to_two_byte_peer_no_trans_no_as4_path`,
`four_byte_asn_to_two_byte_peer_inserts_trans_and_as4_path`,
`four_byte_asn_to_four_byte_peer_no_trans_no_as4_path`,
`as4_path_is_last_attribute_for_two_byte_peer`,
`all_four_byte_asns_to_two_byte_peer_full_trans_substitution`.

### [pathvectord] RFC 4271 correctness audit — fixes (C, D, F, G, K)

**C — NEXT_HOP validation** (`pathvectord/src/daemon.rs`)
`is_valid_next_hop_v4` rejects 0.0.0.0, loopback, multicast (224.0.0.0/4), and broadcast.
Own-address check deferred (FIB oracle reachability gates this anyway).
Tests: `test_invalid_next_hop_*` (3) + `test_valid_next_hop_is_accepted`.

**D — BGP Identifier validation** (`pathvector-session/src/fsm/mod.rs`)
`validate_open` rejects loopback, multicast, and broadcast BGP IDs in addition to 0.0.0.0.
Tests: `test_multicast_bgp_id_rejected`, `test_broadcast_bgp_id_rejected`.

**F — ORIGINATOR_ID and CLUSTER_LIST stripping for eBGP** (`pathvectord/src/outbound.rs`)
`route_to_attributes` strips both when `peer_type == External` (RFC 4456 §8 MUST).
Tests: `test_route_to_attributes_ebgp_strips_originator_id_and_cluster_list`,
`test_route_to_attributes_ibgp_preserves_rr_attributes`.

**G — MED stripping for eBGP** (`pathvectord/src/outbound.rs`)
`route_to_attributes` strips MED when `peer_type == External` (RFC 4271 §5.1.4 SHOULD NOT).
Tests: `test_route_to_attributes_ebgp_strips_med`, `test_route_to_attributes_ibgp_preserves_med`.

**K — IPv6 routes gated on Multi-Protocol capability** (`pathvectord/src/daemon.rs`)
`on_established` gates IPv6 full-table dump and `propagate_to_all_peers_v6` on
`peer_capabilities.contains(MultiProtocol(IPV6_UNICAST))`.
Tests: `test_ipv6_route_not_propagated_to_non_ipv6_capable_peer`,
`test_ipv6_full_table_dump_not_sent_to_non_ipv6_capable_peer`.

**O — Panic/unwrap audit: clean pass**
No crash vectors reachable from peer input, gRPC clients, or config files. All `expect()`
calls in production code are true invariants protected by prior validation guards.

### [cross-cutting] Test coverage expansion (98.0% workspace)

Workspace unit test count increased from ~320 to 376. Key additions:
- `pathvectord/src/fib.rs`: `FibWrite` trait + `MockFibWriter`, `FibManager::new()` spawn
  loop, `DaemonOracle` V6WithLinkLocal branch, V6 error path via `failing_v6()`
- `pathvectord/src/grpc.rs`: `route_v6_to_proto` V4/V6WithLinkLocal/aggregator branches,
  `parse_nlri_v6` error, `originate_route_v6` Incomplete origin, peer-filter mismatch branches
- `pathvectord/src/outbound.rs`: `propagate_prefix`/`_v6` split-horizon and iBGP filtered
  paths, batch-overflow flush tests (fixed 1 000 → 1 500 NLRI threshold), `AtomicAggregate`
  and `AS4_PATH` v6 attr tests
- `pathvector-sys/src/fib/stub.rs`: UFCS tests for all four `FibWrite` trait impl bodies

### [pathvectord] macOS interop fix — DaemonOracle gated on Linux

`KernelFib` on macOS is a no-op stub with an always-empty `FibSnapshot`. Without this fix
`DaemonOracle` marked every peer-learned next-hop unreachable, so `select_best_with_oracle`
excluded all routes from `LocRib.best` — routes were accepted and counted but never selected,
making them invisible in `pv route list` and the dashboard.

Fix: gate oracle construction and `set_oracles()` on `#[cfg(target_os = "linux")]`. On
non-Linux the default `AlwaysReachable` oracle remains in place. No behavioural change on Linux.

---

## 2026-06-15

### [pathvector-rib, pathvectord] DaemonOracle wired into best-path selection (Gap 2)
`DaemonOracle` (wrapping `KernelOracle` → live `FibSnapshot`) is now the oracle used for
all LocRib operations. `DaemonState` holds `oracle_v4/v6: Arc<dyn NextHopOracle + Send + Sync>`,
initialized to `AlwaysReachable` and replaced by `set_oracles()` in `run_with()` before the
event loop starts. All LocRib methods (`insert`, `withdraw`, `withdraw_peer`, `recompute_all`)
receive `Arc::clone(&self.oracle_v4/v6)`. `select_best_with_oracle` filters unreachable
next-hops (step 1) and uses `igp_metric` for the step-8 tiebreaker. RFC 4271 §9.1 steps 1
and 8 are fully live at runtime.

### [pathvector-sys, pathvectord] Stale BGP route cleanup on restart (Gap 4)
`KernelFib::stale_bgp_routes()` dumps all `RTPROT_BGP` routes from the kernel table at daemon
startup. `withdraw_stale_bgp_routes` (extracted `pub(crate) async fn` in `daemon.rs`) iterates
the results and issues `RTM_DELROUTE` via `FibWriter` before the BGP event loop begins. At
startup the Loc-RIB is empty so every kernel BGP route is stale from a previous run; no
convergence signaling is needed. Matches BIRD's `krt` protocol startup behaviour. Two portable
unit tests cover the empty-list no-op and absent-route (ESRCH-suppressed) paths; full
integration coverage deferred to Gap 8 e2e test.

### [pathvector-sys, pathvectord] BGP route feedback loop fix (Gaps 3 & 7 follow-up)
`RTPROT_BGP` routes excluded from `FibSnapshot` (`parse_v4`/`parse_v6` return `None` for BGP
protocol). `apply_new`/`apply_del` return `bool`; `change_tx` fires only on actual snapshot
changes. `fib_change_rx` wired into `run_event_loop` via `watch::Receiver<()>`. `on_fib_change`
on `DaemonState` calls `recompute_all` over both RIBs, pushes diffs to `FibManager`, propagates
changed prefixes to peers. Completes the IGP-change → BGP-reconvergence path.

### [pathvector-rib, pathvectord] LocRib pure data structure + recompute_all (Gaps 2 & 3)
`LocRib` oracle parameter removed from construction; `recompute_best` now takes
`oracle: &dyn NextHopOracle` directly. `recompute_all` iterates all candidates, snapshots
before/after, returns only actual `BestPathChange` entries. `rib_recompute_all_v4/v6` wrappers
on `DaemonState` handle the `Arc::clone` indirection.

## 2026-06-14

### [e2e] BIRD 2 interoperability
BIRD 2 interoperability is fully implemented. `e2e/Dockerfile.bird`, `e2e/fixtures/bird.conf`,
and `BirdHarness` in `e2e/src/lib.rs` are all in place. Eight e2e tests pass against BIRD:

- `bird_static_route_appears_in_pathvectord_rib`
- `bird_multiple_static_routes_appear_in_pathvectord_rib`
- `pathvectord_originated_route_reaches_bird`
- `pathvectord_ebgp_next_hop_is_session_local_addr_not_router_id`
- `bird_route_has_correct_peer_address`
- (additional session + route lifecycle tests)

This work also surfaced and fixed RFC 4271 §5.1.3 bug: pathvectord was advertising the
BGP router ID (`bgp_id`) as the eBGP NEXT_HOP instead of the TCP session's local interface
address. BIRD rejected the routes; GoBGP silently accepted them. Fix: the TCP
`local_addr()` is now threaded through `Session<T>` → `SessionInfo` → `on_established`
→ `RibSnapshot::local_addrs` and used as the NEXT_HOP in `prepare_outbound`.

### [e2e] FRR (FRRouting) interoperability
FRR interoperability is fully implemented. 8 tests pass across `frr_session.rs` and
`frr_routes.rs` (session, peer state, list_peers, route inbound, multiple routes,
route outbound, NEXT_HOP §5.1.3, peer address attribution). FRR confirmed that
pathvectord's NEXT_HOP rewrite is correct end-to-end with a second strict peer.

**FRR config gotchas (recorded for future test work):**
- `no bgp network import-check`: FRR 8.x will not advertise `network` statements
  unless the prefix is present in the kernel FIB. This flag bypasses that check,
  which is required in a container where no kernel routes are installed.
- `no bgp ebgp-requires-policy`: FRR 8.x enforces explicit import/export policy
  on eBGP sessions by default (similar to RFC 8212). Must be disabled for simple
  test configs that don't configure per-session policy.
- `--privileged` Docker flag required: `bgpd` calls `cap_set_proc` for
  `CAP_SYS_ADMIN` during startup for netlink access. `--cap-add=NET_ADMIN` alone
  is insufficient on Docker Desktop (macOS); `--privileged` is needed.
- `frrinit.sh start` exits immediately (starts daemons in background). The
  container CMD must keep PID 1 alive (`|| sleep infinity`) to prevent Docker
  from killing the daemons when the init script exits.

### [pathvector-rib] Criterion benchmark suite
`pathvector-rib` has three criterion benchmark groups (`select_best`, `loc_rib_insert`,
`outbound_pipeline`). Baseline on M2 Max:

| Benchmark | Small | Medium | Large |
|---|---|---|---|
| `select_best` | 4.9 ns (2 candidates) | 35 ns (10) | 526 ns (100) |
| `loc_rib_insert` | 309 ns (10k prefixes) | 293 ns (100k) | 802 ns (500k) |
| `outbound_pipeline` (minimal) | 242 ns (1 peer) | 1.61 µs (10) | 8.59 µs (50) |
| `outbound_pipeline` (dense) | 387 ns (1 peer) | 2.64 µs (10) | 14.4 µs (50) |

Run with `cargo bench -p pathvector-rib`. HTML reports in `target/criterion/`.

### [pathvector-rib] Route reflector support (RFC 4456)
Full RFC 4456 route reflector implementation:
- `ORIGINATOR_ID` (type 9) and `CLUSTER_LIST` (type 10) codec in `pathvector-session`
- `Route<A>` carries both fields through the RIB
- `is_rr_client = true` in peer config + optional `cluster_id` in daemon config
- Inbound: loop detection, ORIGINATOR_ID set on first reflection, CLUSTER_LIST prepend
- Outbound: ORIGINATOR_ID / CLUSTER_LIST included in reflected UPDATE attributes
- Split-horizon: client→client, client↔non-client reflect; non-client→non-client blocked
- 6 new unit tests covering all split-horizon cases and attribute encoding

### [pathvectord / pathvector-sys] FIB integration — IPv6 write path
`FibWriter` has `install_v6` / `withdraw_v6`. `FibManager` has `apply_v6`.
`handle_update` returns `(Vec<BestPathChange<Ipv4Addr>>, Vec<BestPathChange<Ipv6Addr>>)`
and dispatches both families; `on_terminated` and `originate_routes_v6` likewise.

### [pathvectord / pathvector-sys] FIB — RTM_DELROUTE ESRCH silenced
`withdraw_route_v4` and `withdraw_route_v6` both treat `NetlinkError` with code `-3`
(ESRCH) as `Ok(())`.

### [pathvectord / pathvector-sys] FIB — fib_table and fib_metric configurable
`DaemonConfig` has `fib_table: u32` (default 254) and `fib_metric: u32` (default 20);
both are threaded through to `FibWriter::new` and `KernelFib::new`.

### [pathvectord] FIB integration — unit tests for FibManager
10 unit tests cover `apply_v4` (announced/withdrawn/unchanged/no-next-hop), `apply_v6`
(announced/withdrawn/unchanged), and all three `DaemonOracle` `NextHop` variants.
Tests use `FibManager::from_sender` (module-private) to construct without spawning.

---

## 2026-06-13

### [pathvector-session] MD5 authentication (RFC 2385)
`md5_password: Option<String>` TOML field → `SessionConfig` → `apply_tcp_md5sig`
(Linux `setsockopt TCP_MD5SIG`) on the outbound `TcpSocket` before `connect()` and on
the BGP listener socket after `bind()`. No-op with `warn!` on non-Linux (macOS dev).
IPv6 peer MD5 deferred.

### [docs] MD5 interop and testing documentation
Added MD5 interop recipe to `LOCAL_INTEROP.md` and refreshed `TESTING.md` with MD5
safety section, `pathvector-sys` proptest table, and full 41-test e2e scenario table.

### [pathvectord] on_route_update / set_import_default RouteEvents emission
Routes that change best-path during `on_route_update` or `set_import_default` now emit
`RouteEvent`s to the broadcast channel so the dashboard and watch subscribers see live
updates without a reconnect.

---

## 2026-06-12

### [pathvectord] IPv6 RIB — dual-stack
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

### [pathvectord] IPv6 import policy (RFC 8212 parity)
`import_policies_v6: HashMap<Ipv4Addr, Policy<Route<Ipv6Addr>>>` added to
`DaemonState`, initialized with the same `DefaultAction` as `import_policies`
(Reject for eBGP, Accept for iBGP per RFC 8212). `handle_update` applies BLACKHOLE
check + `policy_v6.evaluate()` to all IPv6 announcements.
Test: `test_rfc8212_ebgp_ipv6_reject_without_policy` verifies eBGP routes are
rejected and stored in AdjRibIn for soft-reconfig.

### [e2e] IPv6 interoperability (GoBGP)
Three new e2e tests confirm the full IPv6 wire path against GoBGP 4.6.0:
- `routes.rs::announced_v6_route_appears_in_rib` — GoBGP announces `2001:db8::/32` via
  MP_REACH_NLRI; pathvectord installs it; `get_best_route` returns it with correct attributes
- `routes.rs::withdrawn_v6_route_removed_from_rib` — GoBGP withdraws via MP_UNREACH_NLRI;
  pathvectord removes it from LocRib_v6
- `outbound.rs::originated_v6_route_propagates_to_gobgp` — pathvectord originates
  `2001:db8:1::/48`; GoBGP receives it via MP_REACH_NLRI with NEXT_HOP = `2001:db8::2`
  (eBGP rewrite from `local_ipv6`)
Also fixed: `get_best_route` gRPC handler now queries `loc_rib_v6` for IPv6 prefixes;
`originate_route`/`originate_routes` dispatch to `originate_route_v6` for IPv6 prefixes.

### [pathvectord] Split main.rs into daemon.rs + outbound.rs
The 5865-line file was split into three modules:
- `src/main.rs` (31 lines) — binary entry point only
- `src/daemon.rs` (5240 lines) — `DaemonState`, `RibSnapshot`, `handle_update`,
  `reapply_import_policy`, `run`, `run_bgp_listener`, and all daemon/event/prop tests
- `src/outbound.rs` (605 lines) — all outbound pipeline functions (`propagate_prefix*`,
  `flush_updates*`, `route_*_to_attributes*`) + their unit and property tests
All 214 unit tests pass; `cargo clippy -D warnings` is clean.

### [pathvector-rib / pathvectord] RibView seam
`pathvector-rib` now exports a `RibView<A>` trait with a single
`best(&self, nlri) -> Option<&Route<A>>` method. `LocRib<A>` implements it.
`propagate_prefix` in `pathvectord` is now generic over `impl RibView<Ipv4Addr>` instead
of taking `&LocRib<Ipv4Addr>` directly. A `StubRibView(Option<Route<Ipv4Addr>>)` test
double in `pathvectord`'s test module (3 tests) demonstrates that the Update-Send Process
can be driven with injected best routes — no RIB construction or peer setup required.

### [pathvector-rib / pathvectord] Outbound NLRI batching proptest coverage
Four proptests covering `flush_updates` (IPv4) and `flush_updates_v6` (IPv6) in
`outbound::prop_tests`:
`prop_flush_updates_no_message_exceeds_max_len`, `prop_flush_updates_all_announces_sent`,
`prop_flush_updates_all_withdrawals_sent`, `prop_flush_updates_v6_no_message_exceeds_max_len`.

### [pathvector-client] Streaming mock clients
`MockDaemonClient::peer/route_events` queues implemented; `watch_routes` and `watch_peers`
return configurable event streams for test use. `BoxStream<T>` type alias exported from
`pathvector-client`.

---

## 2026-06-11

### [pathvector] Dashboard — replace polling with streaming
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

### [pathvectord] Connection collision detection
`FsmInput::CollisionDetected` resets the FSM to Active without emitting
`SessionTerminated` (no RIB churn). The transport layer compares `local_bgp_id` vs
`peer_bgp_id` (from the stored peer OPEN) and either adopts the incoming stream or drops
it. `pathvectord` spawns a `TcpListener` on `bgp_port` (default 179, configurable) and
routes accepted connections to per-peer sessions via `SessionCommand::IncomingConnection`.
Tests: `test_collision_detected_in_open_sent/open_confirm_resets_to_active`,
`test_collision_local_wins_adopts_incoming`, `test_collision_peer_wins_keeps_outbound`.

### [pathvectord] RibSnapshot split — eliminate gRPC/event-loop read contention
`DaemonState` now holds `rib: Arc<RibSnapshot>`. gRPC handlers call `snapshot()` to clone
the `Arc` (O(1) atomic increment) and release the outer lock before iterating. The event
loop mutates via `Arc::make_mut` — zero-cost when refcount is 1, copy-on-write only when
a gRPC call is in-flight. See `DECISIONS.md` for full rationale.

**Known concern — CoW under long-lived gRPC streams**: `Arc::make_mut` is zero-cost
when refcount == 1 (the common case). The O(N) clone only fires when a snapshot `Arc`
is held while the event loop mutates state. Streaming handlers must never hold a snapshot
`Arc` across `await` points.

### [e2e] Origination e2e test suite
12 tests in `e2e/tests/origination.rs` covering originated route propagation to GoBGP,
batch origination, withdrawal, idempotent re-origination, attribute preservation
(communities, local_pref, med), blackhole community (RFC 7999), coexistence with
peer-learned routes, and no-op withdrawal of unknown prefix.

---

## 2026-06-10

### [pathvector-session] RFC 7606 — Revised UPDATE error handling
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

### [pathvector-session] ROUTE-REFRESH receive guard
ROUTE-REFRESH received in `Established` is now gated on capability negotiation.
If both sides advertised `RouteRefresh` during OPEN, the message is accepted
(session stays up; full re-advertisement is deferred as a future item).
If not negotiated, the FSM sends FSM Error subcode 3 and tears down the
session. The send direction is a no-op because pathvector never initiates
ROUTE-REFRESH today.
Tests: `test_route_refresh_with_capability_is_accepted`,
`test_route_refresh_without_capability_sends_fsm_error_subcode_3`.

### [pathvector-session] FSM error subcodes 1/2/3
Added `FsmErrorOpenSent`, `FsmErrorOpenConfirm`, `FsmErrorEstablished` variants
to `NotificationError` (wire: code 5, subcodes 1/2/3). The three `_ => vec![]`
wildcards in `on_open_sent`, `on_open_confirm`, and `on_established` now each
send the correct NOTIFICATION and tear down the session when an unexpected
message type arrives.
Tests: `test_unexpected_message_in_open_sent_sends_fsm_error_subcode_1`,
`test_unexpected_message_in_open_confirm_sends_fsm_error_subcode_2`,
`test_unexpected_message_in_established_sends_fsm_error_subcode_3`.

### [pathvector-session] RFC 8654 Extended Message
`BgpCodec` is now stateful; `set_extended_message(true)` raises the frame limit to
65535 bytes after both peers negotiate `Capability::ExtendedMessage` (code 6).
`MAX_LEN`/`MAX_LEN_EXTENDED` are the single source of truth shared between the
framing and message layers. `BgpMessage::decode_with_limit` added for explicit
limit control. Two proptests cover large-message roundtrip and rejection without
negotiation. The transport `execute` loop calls `set_extended_message` in the
`SessionEstablished` arm.

### [pathvector-session] RFC 6286 AS-wide unique BGP ID
`validate_open` rejects iBGP peers that present the same BGP ID as the local speaker
with `NOTIFICATION(BadBgpIdentifier)`; eBGP peers are exempt per the RFC. Two unit
tests cover the accept/reject paths.

### [pathvector-session] RFC 5492 Unsupported Capability
`required_capabilities: Vec<Capability>` added to `FsmConfig`/`SessionConfig`.
`validate_open` emits `NOTIFICATION(UnsupportedCapability)` with capability codes
encoded in the data field when a required capability is absent. Retry after stripping
rejected capabilities is deferred.

### [pathvectord] BLACKHOLE community discard action (RFC 7999)
`handle_update` now checks `raw.communities.iter().any(|c| c.is_blackhole())` before
the import-policy step. BLACKHOLE-tagged routes are stored in `AdjRibIn`
(soft-reconfig visibility) but never installed in `LocRib` or advertised outbound.
Three unit tests cover: not-installed, stored-in-AdjRibIn, and non-BLACKHOLE routes
unaffected.

### [pathvector-client] Route origination API
`originate_route`, `originate_routes`, `withdraw_originated_route`,
`withdraw_originated_routes`, `list_originated_routes` added to `DaemonClient` trait
and implemented on `PathvectorClient`. `OriginateRouteParams` domain type in
`types.rs`; `From` impl in `convert.rs`.

### [pathvector-client] Streaming watch RPCs
`watch_routes(peer: Option<&str>)` and `watch_peers()` as methods on `PathvectorClient`
returning `impl Stream<Item = Result<RouteEvent/PeerEvent, ClientError>>`. Not included
in `DaemonClient` trait (stream types are too complex to mock generically).
`RouteEvent`, `RouteEventType`, `PeerEvent`, `PeerEventType` domain types added.

### [pathvector-client] Route.peer_address Optional
Changed from `IpAddr` to `Option<IpAddr>`; `None` means locally originated route.
`convert.rs` maps proto `"local"` string → `None`; output rendering shows `"local"` for
CLI/dashboard.

### [cross-cutting] Test coverage 97%+ workspace-wide
Comprehensive unit and integration tests added across all crates. Key gaps closed:
grpc origination handlers, watch stream deadlock fix (drop sender before polling),
lib.rs watch conversion closures, transport retry/ExtendedMessage/MpReachNlri paths.
All clippy `-D warnings` errors resolved.

### [pathvectord] Route origination gRPC service and streaming RPCs
`OriginationService` is live on `pathvectord` with five RPCs: `OriginateRoute`,
`OriginateRoutes` (batch), `WithdrawOriginatedRoute`, `WithdrawOriginatedRoutes` (batch),
and `ListOriginatedRoutes`. Routes are injected directly into `LocRib` under the synthetic
`LOCAL_ORIGIN_PEER` (`0.0.0.0`) key, bypassing import policy; export policy still applies
per peer. A single `propagate_to_all_peers` call after the batch completes means N routes
produce ~2 BGP UPDATE messages per peer regardless of N.

`WatchRoutes` and `WatchPeers` streaming RPCs are live on `RibService` and `PeerService`.
Snapshot-then-stream: subscribe to broadcast channel first (no race), send current state as
`CURRENT` events, send `END_INITIAL` sentinel, then stream live deltas. `broadcast::channel`
capacity 1024; slow subscribers receive `RecvError::Lagged` and must reconnect.

---

## 2026-06-09

### [pathvectord] Advertise MultiProtocol(IPv4_UNICAST) capability
Added `Capability::MultiProtocol(AfiSafi::IPV4_UNICAST)` to the session config.
Brings the OPEN into RFC 4760 compliance and causes GoBGP to send IPv4 routes via
MP_REACH_NLRI, exercising the MP code path against a real peer for the first time.
Also the mandatory first step before advertising IPv6 capability.

### [pathvectord] Soft reconfiguration → export propagation
Added `DaemonState::set_import_default` and `set_export_default` methods that update the
relevant policy, call `reapply_import_policy`, and immediately propagate any Loc-RIB
changes to all established peers via `propagate_prefix`. Exposed as `SetImportDefault` /
`SetExportDefault` gRPC RPCs in the new `PolicyService`. Two soft-reconfig e2e tests
confirm the full chain (`e2e/tests/policy.rs`:
`soft_reconfig_import_accept_installs_route`,
`soft_reconfig_export_accept_propagates_to_sink`).

### [pathvector] CLI tool (pathvector crate)
Implemented as `pathvector/` workspace member. Subcommands: `peer list`, `peer get`,
`route list [--peer]`, `route best`, `route candidates`, `policy set-import`,
`policy set-export`, `route originate`, `route withdraw`, `route list-originated`,
`watch routes [--peer]`, `watch peers`, and `dashboard` (live ratatui TUI). Global
`--address` flag + `PATHVECTOR_ADDRESS` env var select the daemon endpoint. `watch routes`
and `watch peers` stream events to stdout until Ctrl-C using `tokio::select!` on the
stream and `tokio::signal::ctrl_c()`.

### [pathvectord] gRPC management API
`PeerService`, `RibService`, and `PolicyService` are live. Proto schema at
`proto/pathvector/v1/management.proto`. See DAEMON.md for the full operational guide
and `grpcurl` examples; see CLI.md for the `pathvector` CLI reference.

### [e2e] End-to-end test suite (Phase 5)
Both gobgpd and pathvectord run as Linux containers on an isolated Docker bridge network
per test. BGP (port 179) is container-to-container — the macOS Docker Desktop TCP proxy
never touches it. Only pathvectord's gRPC port is mapped to the host for
`PathvectorClient`.

20 tests passing across 4 files:
- `routes.rs` (6), `session.rs` (6), `outbound.rs` (4), `policy.rs` (4)

Outbound advertisement tests: `TwoPeerHarness` in `e2e/src/lib.rs`; four tests in
`e2e/tests/outbound.rs` cover: single prefix propagation, multi-prefix, withdrawal,
and management-API visibility.

Import/export-policy reject tests (RFC 8212): `Harness::new_rfc8212()` configures
pathvectord with no policy on the peer; `TwoPeerHarness::new_no_export_policy()`
configures import-accept + no export. Four tests in `e2e/tests/policy.rs` prove both
directions.

### [e2e] GitHub Actions e2e workflow
Separate `e2e` job in `.github/workflows/ci.yml` on `ubuntu-latest` (Docker
pre-installed). Uses `docker/setup-buildx-action` + `docker/build-push-action` with
`type=gha` layer caching (separate scopes for `gobgpd` and `pathvectord` images).
GoBGP image is a cache hit on repeat runs. `test` and `msrv` jobs now pass
`--exclude pathvector-e2e` so the crate is not exercised without its required images.
A `.githooks/pre-push` hook (installed via `just install-hooks`) runs `just e2e`
locally before each push.

### [cross-cutting] try_send stall detection fixed
`propagate_prefix` now returns `bool`; a `false` return means the channel was full.
The three `DaemonState` event methods collect stalled peers into `self.stalled_peers`.
After each event, `run()` sends `SessionCommand::Stop` to each stalled session via a
retained `stop_senders` map (populated from a new `SessionHandle::stop_sender()`
method). The session re-establishes and `on_established` performs a fresh full-table
dump from a clean `AdjRibOut`, restoring a consistent peer view. Overflow is logged
at `ERROR`.

### [pathvectord] Docker image
`e2e/Dockerfile.pathvectord` is a multi-stage build: `rust:1.88-slim-bookworm` builder
(with `protobuf-compiler`), `debian:bookworm-slim` runtime (with `netcat-openbsd` for
HEALTHCHECK). Config file is bind-mounted at container start. gRPC port 51200 is
exposed and mapped dynamically by testcontainers. Built via `just e2e-images`.

### [pathvector-rib] best-path proptests (Phase 2)
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

---

## 2026-06-08

### [pathvectord] gRPC server reflection
`tonic-reflection` registered at startup. `grpcurl` now works without `--proto` flags;
`grpcurl -plaintext localhost:50051 list` discovers all services at runtime.

### [pathvectord] IPv4 MP_REACH_NLRI / MP_UNREACH_NLRI handling
`handle_update` now processes `MP_UNREACH_NLRI` and `MP_REACH_NLRI` attributes for
AFI/SAFI=IPv4 unicast. Peers that send IPv4 withdrawals or announcements via the
multiprotocol attributes instead of the traditional fields are handled correctly.
Non-IPv4 AFI/SAFIs are logged at DEBUG and skipped.

### [pathvector-client] Self-contained gRPC client library
`PathvectorClient::connect(addr)` — lazy channel construction; no async required.
`list_peers()`, `get_peer(addr)`, `get_best_route(prefix)`, `list_routes(peer_filter)`,
`list_candidates(prefix)`. `TryFrom` conversion layer with explicit error variants:
`InvalidAddress`, `UnknownEnumValue`, `BadExtendedCommunityLen`. Three error types:
`ConnectError`, `ClientError`, `ConvertError`. Optional `serde` feature flag on all
domain types.

---

## Earlier (undated / pre-2026-06-08)

### [cross-cutting] RFC_REQUIREMENTS.md
Download of relevant RFCs, requirement extraction, and compliance checking against each
module. `RFC_REQUIREMENTS.md` tracks every implemented RFC, its requirements, owning
module, implementation status, and verified-by test citations.

### [pathvector-session] Message codec and FSM
- Message codec: OPEN, UPDATE, KEEPALIVE, NOTIFICATION, ROUTE-REFRESH
- NLRI parser: variable-length prefix encoding for IPv4 and IPv6
- MP_REACH_NLRI / MP_UNREACH_NLRI for multiprotocol routes
- 4-byte ASN capability — codec encoding/decoding, `AS_TRANS` substitution in FSM,
  `AS4_PATH` / `AS4_AGGREGATOR` handling
- Graceful Restart and Route Refresh capability — codec parsing and encoding
- BGP FSM: Idle → Connect → Active → OpenSent → OpenConfirm → Established
- Codec error logging in transport — `recv_message` errors surfaced via `tracing::warn!`
- **GoBGP interoperability validated (2026-05-31)** — full session lifecycle confirmed:
  OPEN negotiation, KEEPALIVE exchange, UPDATE announce and withdraw, session teardown
- **Outbound UPDATE send path (2026-06-01)** — `SessionHandle::update_sender()` returns
  a cloneable `mpsc::Sender<UpdateMessage>`. `wait_for_input()` wraps its `select!` in a
  `loop` with a lowest-priority arm that writes outbound UPDATEs directly to the TCP
  framer inline; write failures return `TcpFailed` to the FSM for clean recovery.

### [pathvector-session] Panic safety in build_session_info
`build_session_info` now returns `Option<SessionInfo>`. The `on_open_confirm`
Keepalive arm uses `let...else`: on `None` it logs `tracing::error!`, resets the FSM
to Idle, and returns `[StopHoldTimer, StopKeepaliveTimer, CloseTcpConnection]` — the
same clean teardown as a normal failure, without panicking or leaving stale routes.
Covered by `test_keepalive_in_open_confirm_with_missing_peer_open_resets_to_idle`.

### [pathvector-session] Transport layer mocking via BgpTransport trait
`BgpTransport` is a public trait (RPITIT + `+ Send` bounds) in `transport/mod.rs`.
`FramedBgpTransport` is the production impl wrapping `FramedRead`/`FramedWrite` over
TCP. `Session<T: BgpTransport>` is generic; `spawn()` stays non-generic.
`spawn_with<T: BgpTransport>` injects a pre-built transport (ungated — no
`#[cfg(test)]`) so production integrations can supply their own I/O layer.

### [pathvector-session] Hold timer expiry — active FSM enforcement
The hold timer is fully implemented and wired. `wait_for_input` fires
`HoldTimerExpired` when `hold_deadline` elapses; `on_established` sends
`NOTIFICATION(HoldTimerExpired)`, stops timers, closes TCP, and emits
`SessionTerminated`. KEEPALIVE and UPDATE receipt call `reset_hold_if_active()`.

### [pathvector-session] Codec proptests (Phase 1)
All four message types (OPEN, UPDATE, NOTIFICATION, KEEPALIVE, ROUTE-REFRESH) have
round-trip proptests at both the `BgpMessage::encode/decode` layer and the `BgpCodec`
framing layer. Full capabilities, path attributes, and all `NotificationError`
sub-families are exercised. `prop_decode_never_panics` covers both layers.

### [pathvector-policy] Policy semantics proptests (Phase 3)
- `prop_policy_evaluation_is_deterministic`: same route state evaluated twice always
  produces the same decision.
- `prop_first_match_wins_accept_blocks_later_reject`: a route matched by term N
  (Accept) is never passed to term N+1 (catch-all Reject).
Also covers 8 action invariants (PrependAsPath, Add/Remove/SetCommunities,
SetLocalPref, AnyCondition, ActionSequence).

### [pathvectord] TOML config, session spawning, RIB integration, structured logging
- TOML configuration: `local_as`, `bgp_id`, `hold_time`, per-peer `address`/`port`/`remote_as`
- Session spawning: one `transport::spawn()` task per configured peer, events multiplexed
  into a single channel
- RIB integration: `UpdateMessage` → `Route<Ipv4Addr>` conversion, `LocRib`
  insert/withdraw/peer-teardown
- Structured logging via `tracing` with `RUST_LOG` env-filter support
- **GoBGP interoperability validated (2026-05-31)**
- **Outbound advertisement path (2026-06-01)**

### [pathvectord] Import policy + AdjRibIn + RFC 8212 defaults
`handle_update` evaluates a `Policy<Route<Ipv4Addr>>` per route before `LocRib::insert`;
routes that return `Reject` are dropped. Per-peer default action (`import_default =
"accept"` / `"reject"`) is configurable in TOML; eBGP peers default to `"reject"` (RFC
8212) when omitted, iBGP peers default to `"accept"`. `AdjRibIn` per-peer tables built
at startup and wired through `handle_update`. `reapply_import_policy` re-evaluates all
stored raw routes against a new policy.

### [pathvectord] Panic safety in main event loop
All `expect()` calls in `run()` replaced with `let...else` + `tracing::error!` +
`continue`. Unknown peer IPs now log an error and skip the event rather than panicking
the daemon.

### [pathvector-rib] Longest-prefix-match queries
`LocRib::best` now uses `RouteMap<A, (PeerId, Route<A>)>` (routemap 0.1.2) instead of
`HashMap`. `LocRib::longest_match(addr: A)` exposes O(log n) LPM for forwarding lookups.
Exact-prefix queries (`best`, `best_peer`) use the new `RouteMap::get` added in
routemap 0.1.2.

### [pathvectord] Outbound advertisement path (full BGP speaker)
- `ExportDefault` config enum and per-peer `export_default` field
- Per-peer export policies evaluated via `propagate_prefix` before `AdjRibOut` insertion
- `prepare_outbound` applies eBGP attribute transforms: prepend local AS to `AS_PATH`,
  rewrite `NEXT_HOP` to local BGP ID, strip `LOCAL_PREF`
- `route_to_update` / `withdraw_msg` serialise `AdjRibOut` changes to wire-format
  `UpdateMessage`
- On `Established`: `AdjRibOut` reset, full-table dump to new peer
- On `RouteUpdate`: affected NLRIs propagated to all established peers
- On `Terminated`: snapshot-before-withdraw pattern propagates best-path changes;
  `AdjRibOut` reset for clean reconnect
- Idempotent: `propagate_prefix` compares new route against `AdjRibOut` and sends
  UPDATE/WITHDRAW only when advertised state actually changes

### [cross-cutting] Architecture overview document
`ARCHITECTURE.md` at the workspace root covers crate dependency graph, full inbound and
outbound route paths, session lifecycle events table, management plane lock split
rationale, BgpTransport trait seam, and key design invariants.

### [cross-cutting] CI pipeline
`.github/workflows/ci.yml` has five jobs: `test` (stable), `lint` (clippy + rustfmt,
stable), `msrv` (1.88), `docs` (stable, `-D warnings`), and `fuzz` (nightly, `just
fuzz-smoke`). A `Justfile` at the workspace root provides matching local recipes. All
jobs install `protoc`.

### [cross-cutting] cargo fuzz targets (Phase 4)
Two fuzz targets in `fuzz/fuzz_targets/`:
- `session_framing` — feeds raw `&[u8]` into `BgpCodec::decode`; if the framing layer
  accepts a frame, the round-trip encode/decode is also exercised.
- `session_message` — patches the 2-byte length field so `BgpMessage::decode` receives
  a self-consistent buffer, driving body-parsing for all five message types.

Seed corpus pre-populates valid KEEPALIVE, OPEN, NOTIFICATION, UPDATE, and ROUTE-REFRESH
examples. Both targets compile clean under nightly and ran ~3M executions / 16 seconds
with zero panics on first smoke run.

### [pathvectord] FIB integration — partial (KernelFib, FibWriter, FibManager, DaemonOracle)
`KernelFib` (passive FIB tracker), `KernelOracle`, `FibWriter`
(`RTM_NEWROUTE` / `RTM_DELROUTE`), `DaemonOracle` (`NextHopOracle` impl),
`FibManager` (async write queue). `BestPathChange<Ipv4Addr>` is dispatched from
`on_route_update`, `set_import_default`, `on_terminated`, and
`withdraw_originated_routes`. IPv4 routes are installed into the kernel FIB on
best-path change.

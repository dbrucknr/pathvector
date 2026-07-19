# RFC Requirements — pathvector-rib

This crate owns the **routing information base**: Adj-RIB-In, Loc-RIB, Adj-RIB-Out data
structures, the best-path decision process, and outbound route preparation. It has no
wire protocol knowledge and no network I/O.

**Status key:** ✅ Implemented and tested | ⚠️ Partial — see notes | ❌ Not started  
**Verified by key:** `test_name` — unit test | `proptest` — property test | `—` — no automated verification

---

## RFC 4271 §9.1 — Decision Process (Best-Path Selection)

**Owns:** All 10 steps of the BGP decision process applied to competing routes in Loc-RIB.  
**Boundary:** Path attribute type definitions live in `pathvector-types`. Import policy
that filters routes before they enter Adj-RIB-In lives in `pathvector-policy`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4271#section-9.1

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Step 1: Reject routes with unreachable NEXT_HOP | `src/best_path.rs` | ✅ | `test_oracle_unreachable_next_hop_excluded`, `test_oracle_all_unreachable_returns_none`; daemon integration: `test_on_fib_change_withdraws_when_next_hop_goes_down` |
| Step 2: Prefer route with highest LOCAL_PREF; default 100 when absent | `src/best_path.rs` | ✅ | `test_select_best_prefers_higher_local_pref`, `test_select_best_missing_local_pref_treated_as_100`, proptest: `prop_select_best_winner_has_highest_local_pref` |
| Step 3: Prefer locally originated routes (PeerType::Local beats eBGP beats iBGP) | `src/best_path.rs` | ✅ | `test_locally_originated_beats_ebgp`, `test_locally_originated_beats_ibgp`, `test_local_pref_still_overrides_local_origin`, proptest: `prop_select_best_locally_originated_beats_peer_learned` |
| Step 4: Prefer route with shortest AS_PATH length (confed segments count as 0) | `src/best_path.rs` | ✅ | `test_select_best_prefers_shorter_as_path`, proptest: `prop_select_best_winner_has_shortest_as_path` |
| Step 5: Prefer lowest ORIGIN (IGP < EGP < INCOMPLETE) | `src/best_path.rs` | ✅ | `test_select_best_prefers_lower_origin`, proptest: `prop_select_best_winner_has_lowest_origin` |
| Step 6: Prefer lowest MED; same neighboring AS only (RFC 4271 §9.1.2.2) | `src/best_path.rs` | ✅ | `test_select_best_prefers_lower_med`, `test_med_compared_within_same_neighboring_as`, `test_med_ignored_for_different_neighboring_as`, proptest: `prop_select_best_winner_has_lowest_med` |
| Step 7: Prefer eBGP over iBGP (combined with step 3 via PeerType::Ord) | `src/best_path.rs` | ✅ | `test_select_best_prefers_ebgp_over_ibgp` |
| Step 8: Prefer route with lowest IGP metric to next-hop | `src/best_path.rs` | ✅ | `test_oracle_lower_igp_metric_preferred`, `test_oracle_igp_metric_skipped_when_none`; daemon integration: `test_on_fib_change_reannounces_when_next_hop_recovers` |
| Step 9: Prefer oldest eBGP route (received_at: Instant, only when both are eBGP) | `src/best_path.rs` | ✅ | `test_select_best_prefers_older_ebgp_route`, `test_step9_only_applies_to_ebgp` |
| Step 10: (f) Prefer route from peer with lowest BGP Identifier (router-id); skipped if unknown on either side | `src/best_path.rs` | ✅ | `test_select_best_bgp_identifier_overrides_peer_ip_tiebreak`, `test_select_best_falls_back_to_peer_ip_when_bgp_identifier_unknown`, `test_select_best_falls_back_to_peer_ip_when_bgp_identifier_known_on_only_one_side`, proptest: `prop_select_best_lower_bgp_identifier_wins_on_full_tie` |
| Step 11: (g) Prefer route from peer with lowest peer address (final tie-breaker) | `src/best_path.rs` | ✅ | `test_select_best_tiebreak_lower_peer_ip`, proptest: `prop_select_best_lower_peer_ip_wins_on_full_tie` |

**Platform note:** Steps 1 and 8 are active on Linux via `DaemonOracle` wrapping
`KernelFib`. On macOS (development builds) `AlwaysReachable` is used — step 1 never
filters, step 8 is skipped. This is intentional: an empty snapshot on macOS would mark
every next-hop unreachable and drop all peer routes from best-path selection.

---

## RFC 4271 §9.2 — Update-Send Process (RIB Structures)

**Owns:** Adj-RIB-In, Loc-RIB, and Adj-RIB-Out data structures. `AdjRibOut` builds the
set of routes to advertise to each peer after best-path selection and export policy.  
**Boundary:** The Update-Send Process that actually serialises and enqueues BGP UPDATE
messages lives in `pathvectord`. Export policy filtering lives in `pathvector-policy`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4271#section-9.2

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Adj-RIB-In: per-peer table of routes received before import policy | `src/rib.rs` | ✅ | `test_adj_rib_in_insert_and_lookup` |
| Loc-RIB: best-path selected route per prefix | `src/rib.rs` | ✅ | `test_loc_rib_insert_selects_best_path` |
| Adj-RIB-Out: per-peer table of routes after export policy | `src/adj_rib_out.rs` | ✅ | `test_adj_rib_out_insert_and_remove` |
| Withdrawal propagated to all peers' Adj-RIB-Out when best path changes | `src/rib.rs` | ✅ | `test_loc_rib_withdrawal_propagates` |
| `RibSnapshot` captures a consistent point-in-time read of Loc-RIB | `src/snapshot.rs` | ✅ | `test_rib_snapshot_consistency` |

---

## RFC 5065 — AS Confederations for BGP (RIB Layer)

**Owns:** Best-path step 4 confederation handling; confederation segment stripping when
building Adj-RIB-Out for eBGP peers.  
**Boundary:** Confederation segment type definitions (`AS_CONFED_SEQUENCE`, `AS_CONFED_SET`)
and `strip_confed_segments()` helper live in `pathvector-types`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc5065

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Confederation segments (type 3, 4) count as 0 in AS path length for step 4 | `src/best_path.rs` | ✅ | `test_aspath_length_excludes_confed_segments` |
| Confederation segments stripped from AS_PATH before advertising to eBGP peers (§4.1(c)(1)) | `src/adj_rib_out.rs` | ✅ | `test_adj_rib_out_strips_confed_segments_for_ebgp` |
| §4.1(c)(2)-(4): after stripping, prepend the Confederation Identifier into the now-external `AS_SEQUENCE` | — | ❌ | Added 2026-07-16 by `RFC_AUDIT.md` — `strip_confed_segments()` only removes the confed segments; nothing prepends the Confederation Identifier afterward, and `prepare_outbound`'s eBGP prepend uses `local_as` generically with no distinct Confederation-Identifier-vs-Member-AS concept |
| §4.1(b): originate/relay as an actual confederation member (prepend Member-AS Number into `AS_CONFED_SEQUENCE` toward fellow members) | — | ❌ | Added 2026-07-16 — `PeerType` has no representation for "peer in a different Member-AS of the same confederation" at all; only `Internal`/`External`/`Local` exist. This project's RFC 5065 support is pass-through/interop only (correctly strips confed segments from routes that already have them from an upstream confederation), not full confederation-member participation. See `RFC_AUDIT.md`'s "audit-the-audit" section for the full writeup and the open question of whether this is in scope at all. |

---

## RFC 4456 — BGP Route Reflection

**Owns:** Route struct carries `originator_id` and `cluster_list`; `AdjRibOut::new_reflecting`
bypasses iBGP split-horizon so the daemon's propagation loop can implement correct RR semantics.  
**Boundary:** Attribute encoding (wire format) is in `pathvector-session`. Config (`is_rr_client`,
`cluster_id`), inbound attribute processing, and RR split-horizon enforcement are in `pathvectord`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4456

| Requirement | File | Status | Verified by |
|---|---|---|---|
| ORIGINATOR_ID (type 9) stored on Route; carried through LocRib | `src/route.rs` | ✅ | `test_rr_originator_id_and_cluster_list_set_on_reflected_route` (in pathvectord) |
| CLUSTER_LIST (type 10) stored on Route; carried through LocRib | `src/route.rs` | ✅ | `test_rr_originator_id_and_cluster_list_set_on_reflected_route` (in pathvectord) |
| AdjRibOut bypass mode for RR topologies (reflects flag) | `src/adj_rib_out.rs` | ✅ | (exercised by daemon RR tests) |

---

## RFC 4724 — Graceful Restart: Stale Route Timer (Deferred)

**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4724

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Mark routes stale when peer session resets during graceful restart | — | ❌ | — |
| Remove stale routes when restart-time expires | — | ❌ | — |

**Deferred:** Requires coordination with `pathvector-session` (detecting graceful restart
event) and a per-route stale flag. Deferred until graceful restart FSM is implemented.

---

## RFC 9234 — Route Leak Prevention Using Roles in UPDATE and OPEN Messages

**Owns:** `ONLY_TO_CUSTOMER` (OTC) storage on `Route<A>` — a lazily-allocated
`Option<Asn>` field on `RareAttrs`, plus the `BgpRoute::otc()`/`set_otc()`
methods `pathvector-policy`'s conditions/actions read and write.  
**Boundary:** Wire encode/decode of the OTC attribute is in `pathvector-session`.
Leak-detection/prevention policy logic (`OtcLeakCondition`, `SetOtc`,
`OtcPropagationCondition`) is in `pathvector-policy`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc9234

| Requirement | File | Status | Verified by |
|---|---|---|---|
| OTC stored as `Option<Asn>` on `RareAttrs`, lazily allocated like other rare attributes | `src/route.rs` | ✅ | `test_route_builder_otc_defaults_to_none_and_lazily_allocates` |
| `BgpRoute::otc()`/`set_otc()` round-trip on `Route<A>` | `src/route.rs` | ✅ | `test_route_bgproute_otc_getter_and_setter` |
| Setting OTC to `None` on an unallocated `RareAttrs` does not force allocation | `src/route.rs` | ✅ | `test_route_set_otc_none_on_unallocated_rare_does_not_allocate` |
| `.otc(asn)` builder method on `RouteBuilder` | `src/route.rs` | ✅ | (exercised by the getter/setter test above) |

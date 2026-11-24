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
| §9.1.2 "Unresolvable routes SHALL be removed from the Loc-RIB and the routing table" — including when a replacement UPDATE (§9 implicit withdrawal) makes the last feasible candidate unresolvable: `BestPathChange::Withdrawn` | `src/loc_rib.rs` (`BestTransition`) | ✅ | `test_insert_replacing_sole_best_with_unresolvable_next_hop_is_withdrawn` (+ `_v6`), `test_insert_last_feasible_of_several_candidates_is_withdrawn`, `test_insert_all_candidates_become_infeasible_one_by_one`, `test_best_transition_truth_table`; daemon: `daemon::last_feasible_tests` (FIB + WITHDRAWN ROUTES / MP_UNREACH_NLRI, both families) |
| §9.1.2 "unresolvable routes SHOULD be kept in the Adj-RIBs-In (in case they become resolvable)" — kept as Loc-RIB candidates, excluded from selection | `src/loc_rib.rs` | ✅ | `test_insert_unresolvable_replacement_is_kept_as_candidate`, `unresolvable_replacement_of_sole_best_withdraws_from_fib_and_peers_v4` |
| §9.2 "newly unfeasible routes for which there is no replacement route SHALL be advertised": `Withdrawn` only when a best existed and none remains; a feasible alternative yields `Announced`; a never-selected prefix yields `Unchanged` | `src/loc_rib.rs` | ✅ | `test_insert_unresolvable_replacement_promotes_feasible_alternative`, `test_insert_infeasible_into_prefix_without_best_is_unchanged`, `test_withdraw_infeasible_candidate_when_no_best_is_unchanged`, proptest: `prop_loc_rib_change_stream_replays_to_best_table` |

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
| Confederation segments stripped from AS_PATH before advertising to eBGP peers (§4.1(c)(1)) | `src/adj_rib_out.rs`, `src/outbound.rs` | ✅ | `test_adj_rib_out_strips_confed_segments_for_ebgp`, `test_external_strips_confed_before_prepending_public_as` |
| §4.1(c)(2)-(4): after stripping, prepend the Confederation Identifier into the now-external `AS_SEQUENCE` | `src/outbound.rs` | ✅ | `test_external_prepends_public_as_not_local_as`, `test_external_strips_confed_before_prepending_public_as` (also fixes a strip-then-prepend ordering bug found during implementation — see `CHANGELOG.md`) |
| §4.1(b): originate/relay as an actual confederation member (prepend Member-AS Number into `AS_CONFED_SEQUENCE` toward fellow members) | `src/outbound.rs`, `pathvector-types::AsPath::prepend_confed` | ✅ | `test_confed_member_prepends_into_confed_sequence`, `test_confed_member_v6_prepends_into_confed_sequence` |
| §5.3: ConfedMember peer ties with Internal for best-path preference (not eBGP's step 7 win) | `src/best_path.rs` | ✅ | `test_confed_member_ties_with_internal_falls_through_to_tiebreak`, `test_confed_member_beaten_by_external`, `test_confed_member_beaten_by_local` |
| Split-horizon and confed-strip gates correctly exclude ConfedMember (neither Internal-only-suppress nor External-only-strip apply) | `src/adj_rib_out.rs` | ✅ | `test_confed_member_to_confed_member_not_split_horizoned`, `test_confed_segments_preserved_for_confed_member_peer` |
| RFC 1997 `NO_EXPORT` blocks External only; `NO_EXPORT_SUBCONFED` blocks External and ConfedMember | `src/outbound.rs` | ✅ | `test_propagate_prefix_no_export_subconfed_suppresses_ebgp_but_allows_ibgp` (pathvectord), `is_export_suppressed` doc comment |

Shipped 2026-08-04 (`feature/rfc5065-confederation-member-support`), closing the gap `RFC_AUDIT.md`'s 2026-07-16 "audit-the-audit" finding flagged. See `pathvectord/RFC.md` and `pathvector-session/RFC.md` for the config schema, session-classification, and import-side (§5/§6) halves of this work.

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

## RFC 4724 — Graceful Restart: stale routes in the RIB

**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4724 (§4.2 as amended by RFC 8538 §4.1)  
**Boundary:** this crate owns the stale *marking* and its effect (none) on selection; when a
stale route is removed (replacement, End-of-RIB, Restart Time / stale timer) is decided by
`pathvectord` — see its RFC 4724 table.

| Requirement | File | Status | Verified by |
|---|---|---|---|
| §4.2 MUST: mark retained routes "as stale routing information" | `src/route.rs` (`Staleness`), `src/adj_rib_in.rs` (`mark_all_stale`) | ✅ | `adj_rib_in::tests::test_mark_all_stale_marks_every_route_and_keeps_attributes` |
| §4.2 MUST NOT "differentiate between stale and other routing information during forwarding"; RFC 9494 §1 "in conventional GR, route preference is not affected" — a `GrStale` route competes on its attributes | `src/best_path.rs` (`prefer` does not read staleness) | ✅ | `best_path::tests::conventional_gr_*`, `best_path::prop_tests::{prop_conventional_gr_staleness_never_changes_the_winner, prop_prefer_ignores_conventional_gr_staleness, prop_prefer_is_a_strict_total_order}` |
| §4.2 MUST: "replace the stale routes by the routing updates received from the peer" | `src/adj_rib_in.rs` (`insert`) | ✅ | `adj_rib_in::tests::test_reannouncement_replaces_stale_route_with_fresh_one` |
| Staleness is local state, never advertised (no duplicate UPDATE on marking; RFC 9494 §1) | `src/outbound.rs` | ✅ | `outbound::tests::test_prepare_outbound_never_carries_staleness` |

**Corrected 2026-11-23 (issue #68):** `prefer` used to rank any fresh route above any stale
one before `LOCAL_PREF`, and `stale_loses_to_non_stale_before_all_other_criteria` asserted
that while citing RFC 4724 §4.2 — which says the opposite.

### RFC 9494 — Long-Lived Graceful Restart (not implemented)

LLGR is the mechanism that depreferences retained routes ("A least preferred route MUST be
treated as less preferred than any other route that is not also least preferred", §4.4), and
§4.3 applies it only for a speaker that "has advertised the Long-Lived Graceful Restart
Capability". pathvectord never advertises it, so a received `LLGR_STALE` community has no
selection effect here (policy may still match on it, §3.2). `Staleness` is `#[non_exhaustive]`
so an LLGR variant can be added alongside its negotiation, timer and propagation rules.

---|---|---|---|
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

---

## RFC 4271 §5 — Unrecognized Transitive Optional Attribute Storage

**Owns:** `UnknownAttribute` storage on `Route<A>` — a `Vec<pathvector_types::UnknownAttribute>`
field on `RareAttrs`, plus the `.unknown_attribute(attr)` `RouteBuilder` method.  
**Boundary:** Wire encode/decode of `PathAttribute::Unknown` (including setting
the Partial bit on re-encode) is in `pathvector-session`. Deciding which
attributes to store (transitive-only) and forwarding them regardless of peer
type is `pathvectord`'s concern (`handle_update`/`route_to_attributes`).  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4271#section-5

Fixed 2026-08-03 (`feature/rfc4271-unrecognized-transitive-attribute-storage`).
Checked what a real-world implementation does before scoping this: BIRD
(`proto/bgp/attrs.c`) already stores unknown attributes generically as opaque
bytes and re-exports transitive ones with the Partial bit set — confirming
this was a data-model gap, not a deeper architectural problem. Added
`pathvector_types::UnknownAttribute { type_code, value }` rather than having
this crate depend on `pathvector-session`'s wire-level `PathAttribute` type
directly — both crates already depend on `pathvector-types`, so no new
dependency edge between siblings.

| Requirement | File | Status | Verified by |
|---|---|---|---|
| `unknown: Vec<UnknownAttribute>` on `RareAttrs`, lazily allocated like other rare attributes | `src/route.rs` | ✅ | See `pathvectord`'s `handle_update`/`route_to_attributes` tests for the full ingest/egress round-trip |
| `.unknown_attribute(attr)` builder method on `RouteBuilder` (appends, unlike single-value setters) | `src/route.rs` | ✅ | (exercised by `pathvectord`'s tests) |

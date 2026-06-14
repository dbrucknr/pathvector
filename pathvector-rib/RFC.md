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
| Step 1: Reject routes with unreachable NEXT_HOP | `src/best_path.rs` | ❌ | — |
| Step 2: Prefer route with highest LOCAL_PREF; default 100 when absent | `src/best_path.rs` | ✅ | `test_select_best_prefers_higher_local_pref`, `test_select_best_missing_local_pref_treated_as_100`, proptest: `prop_select_best_winner_has_highest_local_pref` |
| Step 3: Prefer locally originated routes (PeerType::Local beats eBGP beats iBGP) | `src/best_path.rs` | ✅ | `test_locally_originated_beats_ebgp`, `test_locally_originated_beats_ibgp`, `test_local_pref_still_overrides_local_origin`, proptest: `prop_select_best_locally_originated_beats_peer_learned` |
| Step 4: Prefer route with shortest AS_PATH length (confed segments count as 0) | `src/best_path.rs` | ✅ | `test_select_best_prefers_shorter_as_path`, proptest: `prop_select_best_winner_has_shortest_as_path` |
| Step 5: Prefer lowest ORIGIN (IGP < EGP < INCOMPLETE) | `src/best_path.rs` | ✅ | `test_select_best_prefers_lower_origin`, proptest: `prop_select_best_winner_has_lowest_origin` |
| Step 6: Prefer lowest MED; RFC requires same-AS comparison only | `src/best_path.rs` | ⚠️ | `test_select_best_prefers_lower_med`, proptest: `prop_select_best_winner_has_lowest_med` |
| Step 7: Prefer eBGP over iBGP (combined with step 3 via PeerType::Ord) | `src/best_path.rs` | ✅ | `test_select_best_prefers_ebgp_over_ibgp` |
| Step 8: Prefer route with lowest IGP metric to next-hop | `src/best_path.rs` | ❌ | — |
| Step 9: Prefer oldest eBGP route (received_at: Instant, only when both are eBGP) | `src/best_path.rs` | ✅ | `test_select_best_prefers_older_ebgp_route`, `test_step9_only_applies_to_ebgp` |
| Step 10: Prefer route from peer with lowest router-id (BGP Identifier) | `src/best_path.rs` | ✅ | `test_select_best_tiebreak_lower_peer_ip`, proptest: `prop_select_best_lower_peer_ip_wins_on_full_tie` |

**Deferred / partial:**
- **Step 1** (next-hop reachability): requires an IGP or FIB integration to determine
  whether a next-hop is reachable. Deferred until a FIB/kernel-route abstraction exists.
- **Step 6** (MED, ⚠️): RFC 4271 §9.1.2.2 requires MED to be compared only between routes
  from the same neighboring AS. The current implementation compares MED globally across all
  peers. This can produce suboptimal selection when routes from different ASes have MED set.
  See the `TODO.md` entry for `deterministic-med` / `always-compare-med`.
- **Step 8** (IGP metric to next-hop): same FIB dependency as step 1.

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
| Confederation segments stripped from AS_PATH before advertising to eBGP peers | `src/adj_rib_out.rs` | ✅ | `test_adj_rib_out_strips_confed_segments_for_ebgp` |

---

## RFC 4456 — BGP Route Reflection (Deferred)

**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4456

| Requirement | File | Status | Verified by |
|---|---|---|---|
| ORIGINATOR_ID attribute (type 9): set on reflection; avoid loops | — | ❌ | — |
| CLUSTER_LIST attribute (type 10): append cluster-id on reflection | — | ❌ | — |
| iBGP split-horizon: do not reflect to peer that originated the route | — | ❌ | — |

**Deferred:** Route reflector support requires a `cluster_id` configuration option and
changes to the iBGP advertisement logic. Deferred until iBGP full-mesh is validated.

---

## RFC 4724 — Graceful Restart: Stale Route Timer (Deferred)

**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4724

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Mark routes stale when peer session resets during graceful restart | — | ❌ | — |
| Remove stale routes when restart-time expires | — | ❌ | — |

**Deferred:** Requires coordination with `pathvector-session` (detecting graceful restart
event) and a per-route stale flag. Deferred until graceful restart FSM is implemented.

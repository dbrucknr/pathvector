# RFC Requirements — pathvectord

This crate owns the **daemon integration layer**: the gRPC service, session orchestration,
Update-Send Process, attribute transforms, and policy defaults. It is the only crate in
the workspace that ties all other crates together.

**Status key:** ✅ Implemented and tested | ⚠️ Partial — see notes | ❌ Not started  
**Verified by key:** `test_name` — unit test | `interop:x` — GoBGP interop | `e2e:x` — end-to-end test | `—` — no automated verification

---

## RFC 4271 §9 / §9.1.1 — Import (Phase 1) and Implicit Withdrawal

**Owns:** `daemon/import.rs`: `ImportDecision`, `import_announcement` and
`reapply_import_policy`, the one path (both address families) by which a received
route goes through import policy into the Loc-RIB, on arrival and on re-evaluation.  
**Boundary:** Policy evaluation lives in `pathvector-policy`; candidate storage and
best-path selection (§9.1.2) live in `pathvector-rib`; FIB and outbound side effects stay
with the caller (`DaemonState::on_route_update`, `reevaluate_import_for_peer`).  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4271#section-9

Clauses implemented (quoted from the RFC text):

- §9: "if the NLRI of the new route is identical to the one the route currently has
  stored in the Adj-RIB-In, then the new route SHALL replace the older route in the
  Adj-RIB-In, thus implicitly withdrawing the older route from service."
- §9.1: Phase 1 returns a preference or "a value denoting that this route is ineligible
  to be installed in Loc-RIB and will be excluded from the next phase of route selection."
- §9.1.2: "The Phase 2 process considers all routes that are eligible in the Adj-RIBs-In."
- RFC 9234 §3/§5: a leaked route "MUST be considered ineligible", with RFC 4271's meaning.

RFC 7606 does not apply: it revises error handling for *malformed* UPDATEs and does not
mention policy. A policy rejection is a well-formed route found ineligible.

| Requirement | File | Status | Verified by |
|---|---|---|---|
| A replacement route replaces the peer's older route in Adj-RIB-In (pre-policy), whether or not policy accepts it, so later re-evaluation judges the latest advertisement | `src/daemon/import.rs` `import_announcement` | ✅ | `import_announcement_keeps_rejected_replacement_in_adj_rib_in`, `rov_invalid_replacement_withdraws_and_reevaluates_replacement_v4`/`_v6` |
| A replacement that import policy rejects withdraws the peer's older Loc-RIB candidate; with no other candidate the FIB gets `Withdrawn` and peers get WITHDRAWN ROUTES / `MP_UNREACH_NLRI` (§9.2) | `src/daemon/import.rs` `ImportDecision::apply` | ✅ | `rejected_replacement_of_sole_best_withdraws_from_fib_and_peers_v4`/`_v6` (issue #80) |
| …and another peer's eligible route takes over: FIB switches next hop, peers get a replacement, never a withdrawal | `src/daemon/import.rs` | ✅ | `rejected_replacement_promotes_other_peers_route_v4`/`_v6` |
| …and a rejected replacement of a non-selected candidate removes it without FIB or peer churn | `src/daemon/import.rs` | ✅ | `rejected_replacement_of_losing_candidate_causes_no_churn_v4`/`_v6` |
| An accepted replacement of a rejected route is installed and advertised | `src/daemon/import.rs` | ✅ | `accepted_replacement_of_rejected_route_is_installed_v4`/`_v6` |
| The same holds for RFC 6811 ROV Invalid and RFC 9234 §5 OTC-leak replacements | `src/daemon/import.rs` | ✅ | `rov_invalid_replacement_withdraws_and_reevaluates_replacement_v4`/`_v6`, `otc_leak_replacement_withdraws_old_route_v4`/`_v6` |
| Model: after any per-peer sequence of accepted/rejected announcements and withdrawals, Loc-RIB candidates == each peer's latest advertisement that passed policy; Adj-RIB-In == latest advertisement; re-evaluation agrees with initial import | `src/daemon/import_reject_tests.rs` | ✅ | `prop_loc_rib_candidates_are_latest_accepted_advertisement_per_peer` |
| Replacements dropped *before* import policy (AS loop, AS 0, invalid NEXT_HOP) also implicitly withdraw the older route | `src/daemon/ingress.rs`, `src/daemon/route.rs` | ✅ | See the next section (issue #138) |

---

## RFC 4271 §9 / §9.1.2 / §6.3 — Announcements Dropped Before Import Policy

**Owns:** `daemon/ingress.rs`: `IngressGate` (pure: AS_PATH and next-hop verdicts),
`IngressDrop` (the reason) and `Disposition` (what the reason does to the peer's older
route). `route.rs` applies the verdict (`withdraw_route`, `import_ineligible`);
`import.rs` re-applies it on soft reconfiguration.  
**Boundary:** No RIB access in `ingress.rs`. Policy stays in `pathvector-policy`; the
Adj-RIB-In/Loc-RIB reconciliation is the same `ImportDecision::Rejected` path as the
import-policy case above (issue #80).  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4271#section-9.1.2

Before issue #138 these announcements were dropped with a bare `continue`, so the older
route the *same peer* advertised for the same NLRI stayed in the Adj-RIB-In, selected,
installed in the FIB and advertised, although the peer had replaced it.

Clauses (quoted from the RFC text):

- RFC 4271 §9: "the new route SHALL replace the older route in the Adj-RIB-In, thus
  implicitly withdrawing the older route from service."
- RFC 4271 §9.1.2: "If the AS_PATH attribute of a BGP route contains an AS loop, the
  BGP route should be excluded from the Phase 2 decision function." Excluded, not
  discarded: the route is *ineligible*, so it replaces the older route (§9) and the peer
  is left with no candidate.
- RFC 5065 §4: "A BGP speaker receiving an AS_PATH attribute containing an autonomous
  system matching its own AS Confederation Identifier SHALL treat the path in the same
  fashion as if it had received a path containing its own AS number."
- RFC 4271 §6.3: "Syntactic correctness means that the NEXT_HOP attribute represents a
  valid IP host address." The error is Invalid NEXT_HOP Attribute (session reset), which
  RFC 7606 §3(e) replaces: "'Treat-as-withdraw' MUST be used for the cases that specify a
  session reset and involve any of the attributes ORIGIN, AS_PATH, NEXT_HOP, ...".
  RFC 7606 §2: the routes are handled "just as if they had been listed in the WITHDRAWN
  ROUTES field", "thus causing them to be removed from the Adj-RIB-In".
- RFC 4271 §6.3 (a): the NEXT_HOP "MUST NOT be the IP address of the receiving speaker";
  if it is, "the error SHOULD be logged, and the route SHOULD be ignored. In this case, a
  NOTIFICATION message SHOULD NOT be sent, and the connection SHOULD NOT be closed." No
  session reset is specified, so RFC 7606 §3(e) does not apply; RFC 7606 §7.3 only covers
  a NEXT_HOP of the wrong length.
- RFC 7607 §2 prohibits AS 0 in AS_PATH and delegates the handling of such an UPDATE to
  RFC 7606, i.e. treat-as-withdraw.

Decisions, and why:

| Reason | Disposition | Adj-RIB-In | Loc-RIB | Basis |
|---|---|---|---|---|
| AS loop (local AS or Confederation Identifier) | `Ineligible` | holds the replacement | no candidate | §9.1.2 "excluded from the Phase 2 decision function"; §9 replacement |
| Own address as NEXT_HOP | `Ineligible` | holds the replacement | no candidate | §6.3 (a) "SHOULD be ignored", read as *not used*; the route still supersedes the older one (§9), so keeping the superseded route would contradict §9 |
| Unspecified, loopback, multicast or broadcast IPv4 NEXT_HOP; unspecified or multicast IPv6 next hop (incl. a multicast link-local) | `TreatAsWithdraw` | removed | no candidate | §6.3 syntax + RFC 7606 §3(e), §2 (RFC 1122 §3.2.1.3 and RFC 4291 §2.5.2 / §2.7 say these are not host addresses) |
| AS 0 in AS_PATH | `TreatAsWithdraw` | removed | no candidate | RFC 7607 §2 → RFC 7606 |
| AS_SET or AS_CONFED_SET in AS_PATH | `TreatAsWithdraw` | removed | no candidate | RFC 9774 §3 |

Notes:

- A syntactically invalid **NEXT_HOP attribute** is treat-as-withdraw for the *whole
  UPDATE*: RFC 7606 §3(e) selects the approach and §2 defines it over the UPDATE
  ("all contained routes"), so every NLRI it announces — classic NLRI field, MP_REACH
  IPv4 and MP_REACH IPv6 — is withdrawn (`handle_update`, before the announcement loops;
  test `invalid_next_hop_attribute_withdraws_every_nlri_of_the_update`). An invalid
  *MP_REACH_NLRI* next hop is not the NEXT_HOP attribute, so it stays scoped to that
  attribute's own NLRI (`invalid_mp_reach_next_hop_withdraws_only_its_own_nlri_v4_good_v6_bad`).
  RFC 4760 §3 carves out the MP-only case: an UPDATE "that carries no NLRI, other than the
  one encoded in the MP_REACH_NLRI attribute, SHOULD NOT carry the NEXT_HOP attribute. If
  such a message contains the NEXT_HOP attribute, the BGP speaker that receives the message
  SHOULD ignore this attribute." RFC 7606 does not remove it, so the attribute is checked
  only when the classic NLRI field uses it
  (`unused_classic_next_hop_is_ignored_when_mp_reach_is_the_only_nlri`).
  Our own address as NEXT_HOP is semantic (§6.3 (a)), so it is per-route `Ineligible`.
- If both an `Ineligible` and a `TreatAsWithdraw` reason apply, treat-as-withdraw wins
  (`IngressDrop::most_severe`).
- An `Ineligible` route stays in the Adj-RIB-In for soft reconfiguration, so every path
  that turns Adj-RIB-In routes into candidates asks the same `IngressGate` first:
  `reapply_import_policy`, and Graceful Restart stale marking (`mark_stale_and_repropagate`
  re-imports each retained route through `ImportPipeline::classify_gated` — gate, BLACKHOLE agreement, import policy (issue #82); RFC 4724 §4.2
  retains routes, it does not make an ineligible one eligible). The gate is built before
  teardown forgets the local address, and `GracefulRestartState::retained_local_v4` keeps our
  last address toward the peer for the life of the retained routes, so own-NEXT_HOP routes stay
  rejected through later soft reconfiguration too
  (`own_next_hop_stays_rejected_through_soft_reconfiguration_in_the_gr_window`). It counts toward
  max-prefix like a policy-rejected route.
- A BLACKHOLE-tagged (RFC 7999) announcement that is dropped is stored like any other
  ineligible replacement (RFC 4271 §9; RFC 7999 §3.3 encourages keeping them) but owns no null
  route: ownership is recorded in `BlackholeBook`, not read off the stored route's communities
  (issue #81 replaced the earlier `holds_blackhole` tag scan, which is why the tag no longer
  has to be discarded). An older BLACKHOLE route superseded by a dropped announcement releases
  its claim, and the null route is withdrawn when no other peer holds the prefix
  (`dropped_replacement_of_a_blackhole_route_withdraws_the_null_route`,
  `dropped_blackhole_announcement_owns_no_null_route_and_its_withdrawal_removes_none`).
- The AS 0 and set rows are also enforced by the session decoder (see
  `pathvector-session/RFC.md`), so a wire UPDATE reaches the daemon already turned into
  withdrawals; the gate holds them for a session implementation that does not use that
  decoder.

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Dropped replacement of the sole best route: FIB `Withdrawn`, peers get WITHDRAWN ROUTES / `MP_UNREACH_NLRI`, no NOTIFICATION (§9, §9.2) | `src/daemon/route.rs` | ✅ | `dropped_replacement_of_sole_best_withdraws_from_fib_and_peers_v4`/`_v6` (AS loop, confederation-ID loop, AS 0, unspecified/loopback/multicast/broadcast NEXT_HOP, own-address NEXT_HOP) |
| …another peer's route takes over, peers never see a withdrawal | `src/daemon/route.rs` | ✅ | `dropped_replacement_promotes_other_peers_route_v4`/`_v6` |
| No earlier route from the peer: no FIB change, nothing sent, other peers' routes untouched | `src/daemon/route.rs` | ✅ | `dropped_announcement_without_earlier_route_is_a_no_op_v4`/`_v6` |
| Adj-RIB-In: removed for treat-as-withdraw, holds the replacement for ineligible routes | `src/daemon/route.rs` | ✅ | `assert_adj_rib_in_v4`/`_v6` in every test above |
| Several NLRI in one UPDATE: an invalid NEXT_HOP attribute withdraws all of them; loops and MP_REACH next hops affect only their own NLRI | `src/daemon/route.rs` | ✅ | `invalid_next_hop_attribute_withdraws_every_nlri_of_the_update`, `invalid_mp_reach_next_hop_withdraws_only_its_own_nlri_v4_good_v6_bad`, `loop_update_with_several_nlri_withdraws_only_prefixes_with_an_earlier_route`, `loop_update_with_several_v6_nlri_withdraws_only_prefixes_with_an_earlier_route` |
| Re-evaluation does not resurrect an ineligible replacement | `src/daemon/import.rs` | ✅ | `reevaluation_keeps_an_ineligible_replacement_out_of_the_loc_rib` |
| Graceful Restart stale marking does not resurrect ineligible (or policy-rejected) routes, including own-NEXT_HOP after the local address is forgotten; eligible routes are still retained | `src/daemon/gr.rs` | ✅ | `graceful_restart_does_not_resurrect_ineligible_routes`, `graceful_restart_does_not_resurrect_policy_rejected_routes`, `graceful_restart_still_retains_eligible_routes` |
| A dropped BLACKHOLE announcement is not retained; its withdrawal removes no other peer's null route | `src/daemon/route.rs` | ✅ | `dropped_blackhole_announcement_is_not_retained_and_withdrawal_removes_no_null_route` |
| An eligible route after a dropped one is installed | `src/daemon/route.rs` | ✅ | `eligible_replacement_of_a_dropped_route_is_installed` |
| A superseded BLACKHOLE route's null route is withdrawn | `src/daemon/route.rs` | ✅ | `dropped_replacement_of_a_blackhole_route_withdraws_the_null_route` |
| Model: after any per-peer sequence of accepted / ineligible / treat-as-withdraw announcements and withdrawals, candidates == latest accepted advertisement, Adj-RIB-In as the table above says, re-evaluation agrees | `src/daemon/ingress_drop_tests.rs` | ✅ | `prop_dropped_announcements_leave_the_peer_with_no_candidate` |
| Verdicts and dispositions as pure values | `src/daemon/ingress.rs` | ✅ | `ingress::tests::*` |
| e2e: real session, AS-loop and 0.0.0.0-NEXT_HOP replacements withdraw the first route, session stays up | `pathvector-e2e` | ✅ | `as_loop_replacement_withdraws_the_older_route_session_stays_up`, `invalid_next_hop_replacement_withdraws_the_older_route_session_stays_up` |

---

## RFC 4271 §9.2 — Update-Send Process

**Owns:** `propagate_prefix`, `prepare_outbound`, and `flush_updates`: the pipeline that
takes a best-path change in Loc-RIB, applies export policy and attribute transforms, and
enqueues BGP UPDATE messages to each peer's write task.  
**Boundary:** Adj-RIB-Out data structures live in `pathvector-rib`. Wire serialisation
of UPDATE messages lives in `pathvector-session`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4271#section-9.2

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Mandatory attributes (ORIGIN, AS_PATH, NEXT_HOP) checked on arrival; absent → NOTIFICATION with RFC 4271 §6.3 data field containing missing attr type code | `src/daemon.rs` | ✅ | `missing_origin_returns_notification_data_type_code_1`, `missing_as_path_returns_notification_data_type_code_2`, `missing_next_hop_for_traditional_ipv4_returns_notification_data_type_code_3`, `withdraw_only_update_no_notification_for_missing_attrs`, `malformed_update_missing_origin_sends_notification_to_session` |
| LOCAL_PREF stripped when advertising to eBGP peers | `src/outbound.rs` | ✅ | `test_prepare_outbound_ebgp_strips_local_pref` |
| AS_PATH prepended with local ASN before advertising to eBGP peers | `src/outbound.rs` | ✅ | `test_prepare_outbound_ebgp_prepends_local_as`, `test_propagate_prefix_ebgp_prepends_local_as_in_wire_message` |
| NEXT_HOP rewritten to TCP session local interface address for eBGP peers (RFC 4271 §5.1.3) | `src/outbound.rs`, `src/daemon.rs` | ✅ | `test_prepare_outbound_ebgp_rewrites_next_hop`, `test_on_established_ebgp_next_hop_uses_local_addr_not_router_id`, `test_propagate_to_all_peers_ebgp_next_hop_uses_local_addr`, e2e: `pathvectord_ebgp_next_hop_is_session_local_addr_not_router_id` |
| iBGP peers pass-through: LOCAL_PREF preserved, AS_PATH unchanged, NEXT_HOP unchanged | `src/outbound.rs` | ✅ | `test_prepare_outbound_ibgp_preserves_attributes` |
| LOCAL_PREF received from an eBGP peer MUST be ignored by the receiving speaker, except confederation Member-AS peers (RFC 4271 §5.1.5, RFC 5065 §5.2) | `src/daemon/route.rs` | ✅ | `test_local_pref_ignored_from_ebgp_peer`, `test_local_pref_honored_from_ibgp_peer`, `test_local_pref_honored_from_confed_member_peer`, `test_ebgp_local_pref_cannot_win_best_path_over_shorter_as_path`. Original eBGP-ignore gap fixed 2026-07-xx (`RFC_AUDIT.md` §5); widened to the RFC 5065 confederation exception 2026-08-04 (`feature/rfc5065-confederation-member-support`). |
| Withdrawal sent to all peers when a best path is removed | `src/daemon.rs` | ✅ | `test_propagate_prefix_sends_withdraw_when_route_removed`, `test_on_terminated_propagates_withdraw_to_other_established_peers` |
| eBGP split-horizon: route received from eBGP peer not re-advertised back to that peer | `src/daemon.rs` | ✅ | `test_propagate_prefix_ebgp_source_peer_not_readvertised` |
| iBGP split-horizon: route received from iBGP peer not re-advertised to other iBGP peers | `src/daemon.rs` | ✅ | `test_propagate_prefix_ibgp_split_horizon_no_send`, `test_propagate_prefix_ibgp_split_horizon_eviction_sends_withdraw` |
| NLRI batching: announcements with same path attributes packed into fewest UPDATEs within `max_len` | `src/outbound.rs` | ✅ | `test_flush_same_attrs_batched_into_one_message`, `test_flush_splits_when_exceeding_max_len`, `test_flush_withdrawal_split_delivers_all_nlris` |
| Announcement groups with distinct path attributes go into separate UPDATEs | `src/outbound.rs` | ✅ | `test_flush_different_attrs_two_messages` |
| Withdrawals sent before announcements; withdrawal list packed within `max_len` | `src/outbound.rs` | ✅ | `test_flush_withdrawals_before_announces`, `test_flush_withdrawal_split_delivers_all_nlris` |
| Applying the UPDATEs in the order sent yields the Adj-RIB-Out (§3.1 withdrawal and replacement, §9.2): a batch sends only the last announce/withdraw per NLRI, and every route-carrying send drains the peer's coalescing buffer, so nothing overtakes an older decision (issue #159) | `src/outbound.rs` `retain_last_per_nlri`, `src/daemon/route.rs` `flush_peer` | ✅ | `src/daemon/outbound_order_tests.rs`: `event_loop_announce_then_withdraw`, `event_loop_announce_then_session_loss`, `replaced_announcement_sharing_a_group_leaves_the_replacement`, `sent_updates_always_match_adj_rib_out` (property) |
| RFC 4760 §3: one `MP_REACH_NLRI` carries only prefixes that share its next hop | `src/outbound.rs` `flush_updates_v6` | ✅ | `v6_prefixes_with_different_next_hops_keep_their_own` |
| Unrecognized transitive optional attributes stored on ingest (Optional+Transitive flags only; non-transitive quietly dropped) and forwarded unconditionally on egress regardless of peer type, with the Partial bit set (RFC 4271 §5) | `src/daemon/route.rs`, `src/outbound.rs` | ✅ | Fixed 2026-08-03 (`feature/rfc4271-unrecognized-transitive-attribute-storage`). See `RFC_AUDIT.md` §5 and `pathvector-rib/RFC.md`'s own section for the storage half. `test_handle_update_stores_unrecognized_transitive_attribute`, `test_handle_update_quietly_ignores_unrecognized_non_transitive_attribute`, `unrecognized_transitive_attribute_is_forwarded_with_optional_transitive_flags` |
| e2e (2026-08-05, Codex review of PR #49): the complete decode → daemon storage → RIB → outbound-reconstruction → encode pipeline through a real two-hop relay, not just decode-level and daemon-storage-level unit tests — asserting the exact re-encoded flags octet, which a GoBGP CLI's rendered RIB text cannot express | `pathvector-e2e/src/bin/mock_bgp_attr_peer.rs`, `pathvector-e2e/tests/unknown_transitive_attribute.rs` | ✅ | `unknown_transitive_attribute_relayed_with_partial_bit_set` (a `source` mock injects an unrecognized Optional+Transitive attribute, Partial bit clear, plus an unrecognized Optional-only non-transitive negative control; an `observer` mock decodes pathvectord's re-advertised UPDATE with the real wire codec and confirms the transitive attribute survives with its value unchanged and Partial bit now set, while the non-transitive one is absent entirely) |

---

## RFC 4271 §9.2.1.1 — Minimum Route Advertisement Interval (MRAI)

**Owns:** eBGP MRAI enforcement, per destination, for IPv4 and IPv6 unicast: a
re-announcement of a destination inside the 30-second interval is held back and the
last route selected is announced when the interval expires. Withdrawals bypass MRAI
(documented deviation, below).  
**Boundary:** Wire serialisation lives in `pathvector-session`. The gate
(`MraiTracker::gate` in `src/daemon/route.rs`) wraps each destination's Adj-RIB-Out
diff: a held-back announcement is rolled back out of the Adj-RIB-Out, so the
Adj-RIB-Out always holds what the peer was actually sent, and the release at expiry
diffs against that.  
**Amendments checked (2026-11-23):** none of RFC 4271's updating RFCs (4724, 6286,
6608, 6793, 7606, 7607, 7705, 8212, 8654, 9072, 9687, 9774) touches §9.2.1.1. RFC 4760
does not exempt MP_REACH_NLRI, and the clause is per destination, so it applies to
IPv6 unicast as well.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4271#section-9.2.1.1

| Requirement | File | Status | Verified by |
|---|---|---|---|
| 30 s MRAI for eBGP peers; re-announcement of a destination within the interval held back | `src/daemon/route.rs` | ✅ | `suppressed_replacement_is_sent_when_mrai_expires_v4` (`daemon/mrai_flush_tests.rs`), `destination_sent_just_now_is_not_ready` |
| "the last route selected SHALL be advertised at the end of MinRouteAdvertisementIntervalTimer" — the held-back replacement actually reaches the peer at expiry | `src/daemon/route.rs` | ✅ | `suppressed_replacement_is_sent_when_mrai_expires_v4`, `last_route_selected_during_window_is_the_one_sent_v4` — **fixed 2026-11-23:** the replacement used to be committed to the Adj-RIB-Out before the MRAI check, so the release at expiry diffed to `NoChange` and the peer kept the stale path indefinitely |
| Selection that reverts to the advertised route within the interval sends nothing extra | `src/daemon/route.rs` | ✅ | `replacement_reverted_within_window_never_sends_intermediate_v4` |
| Adj-RIB-Out (and `show adj-rib-out` / advertised counters) reflects what was sent, not what is held back | `src/daemon/route.rs` | ✅ | `adj_rib_out_holds_route_actually_sent_while_suppressed_v4` |
| Same interval for IPv6 unicast (MP_REACH_NLRI) | `src/daemon/route.rs` | ✅ | `suppressed_replacement_is_sent_when_mrai_expires_v6` — **added 2026-11-23**; the IPv6 path previously applied no MRAI at all |
| Held-back destinations released by the MRAI/2 timer; per-destination readiness | `src/daemon/route.rs` | ✅ | `take_ready_releases_only_elapsed_destinations`, `flush_mrai_pending_clears_elapsed_pending`, `regression_flush_mrai_pending_requires_subsequent_flush_pending` |
| Withdrawals bypass MRAI; a withdrawal cancels a held-back announcement | `src/daemon/route.rs` | ⚠️ | `withdrawal_within_window_is_sent_immediately_v4`/`_v6`, `suppressed_replacement_then_withdrawal_sends_only_withdrawal_v4`/`_v6` — **deliberate deviation.** RFC 4271 §9.2.1.1 applies the interval to "advertise feasible routes **and/or withdrawal of unfeasible routes**" (see `RFC_AUDIT.md` §9.2.1.1). The behaviour follows RFC 1771 §9.2.3.1, which RFC 4271 replaced: "To avoid long-lived black holes, the procedure does not apply to the explicit withdrawal of unfeasible routes." Holding back a withdrawal keeps a blackholed path alive at the peer, so pathvectord accepts the deviation. |
| iBGP MRAI (SHOULD be shorter than eBGP, or not applied, per RFC 4271 §9.2.1.1) | `src/daemon/route.rs` | ✅ | `ibgp_peer_is_not_rate_limited_v4` — option (b), "the procedure [...] SHOULD NOT apply to routes sent to internal peers": the gate is skipped for iBGP peers |

**Not covered:** only `propagate_to_all_peers`/`_v6` (UPDATE processing, policy
changes, origination, FIB-driven next-hop changes, and the MRAI release itself) pass
through the gate. Announcements made by the session-termination
(`on_terminated`), graceful-restart, and selection-deferral release paths call
`propagate_prefix` directly. They are neither rate-limited nor recorded as starting an
interval, and neither is the initial table dump. They commit exactly what they send,
so they cannot strand a peer on a stale path. A withdrawal clears the destination's
last-sent stamp, so a re-announcement right after a withdrawal goes out immediately.

---

## RFC 6793 — Four-Octet AS Number Capability (Outbound Encoding)

**Owns:** Outbound AS_PATH encoding for 2-byte-only peers: substituting 4-byte ASNs with
AS_TRANS (23456) and appending the original path as AS4_PATH (type 17, flags 0xC0 =
optional+transitive) so downstream 4-byte-capable routers can reconstruct the full path.  
**Boundary:** `Asn::TRANS` constant, `AsPath::downgrade_for_two_byte_peer()` and the
`As4Path` construction rule live in `pathvector-types`. The wire form (two-octet `AS_PATH`/`AGGREGATOR`, AS_TRANS, and a
generated `AS4_PATH`/`AS4_AGGREGATOR` if the daemon did not attach one) and inbound AS4_PATH
merging (receiving from 2-byte peers) are owned by `pathvector-session`, which the daemon
reaches through the negotiated `AsnWidth`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc6793#section-4

| Requirement | File | Status | Verified by |
|---|---|---|---|
| 4-byte ASNs replaced by AS_TRANS in wire AS_PATH for 2-byte-only peers | `src/outbound.rs` | ✅ | `four_byte_asn_to_two_byte_peer_inserts_trans_and_as4_path` |
| Original 4-byte ASNs preserved in AS4_PATH attribute for 2-byte-only peers | `src/outbound.rs` | ✅ | `four_byte_asn_to_two_byte_peer_inserts_trans_and_as4_path`, `all_four_byte_asns_to_two_byte_peer_full_trans_substitution` |
| No AS_TRANS / AS4_PATH for 4-byte-capable peers | `src/outbound.rs` | ✅ | `four_byte_asn_to_four_byte_peer_no_trans_no_as4_path` |
| No AS4_PATH when all ASNs fit in 2 bytes (no substitution occurred) | `src/outbound.rs` | ✅ | `two_byte_asns_to_two_byte_peer_no_trans_no_as4_path` |
| AS4_PATH appears as last attribute (2-byte speakers can skip unknown optional attributes) | `src/outbound.rs` | ✅ | `as4_path_is_last_attribute_for_two_byte_peer` |
| No AS4_PATH when the only four-byte ASN is in a confed segment (§4.2.2 "MUST NOT send" — nothing non-mappable left after stripping confed) | `src/outbound.rs` `push_as4_side_channel` | ✅ | `no_as4_path_when_the_only_four_byte_asn_is_in_a_confed_segment` |
| AS4_AGGREGATOR for a non-mappable aggregating AS toward a 2-byte peer; never for a mappable AS or a 4-byte peer | `src/outbound.rs` `push_as4_side_channel` | ✅ | `as4_aggregator_only_for_non_mappable_aggregator_toward_two_byte_peer` |
| E2e verification against real 2-byte-only peer (GoBGP `--as2` mode) | — | ❌ | — |

**Deferred:** E2e test against GoBGP in 2-byte-only mode to verify wire format on a live session.

---

## RFC 4760 — Multiprotocol Extensions (Daemon Processing)

**Owns:** Daemon-level processing of MP_REACH_NLRI and MP_UNREACH_NLRI: extracting
prefixes and next-hops from decoded attributes, inserting into Adj-RIB-In + Loc-RIB,
and propagating to peers. Currently only IPv4 unicast and IPv6 unicast are processed;
other address families are silently ignored.  
**Boundary:** MP_REACH_NLRI / MP_UNREACH_NLRI codec lives in `pathvector-session`. AFI/SAFI
registry lives in `pathvector-types`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4760

| Requirement | File | Status | Verified by |
|---|---|---|---|
| IPv4 unicast inbound: insert/withdraw into Loc-RIB via traditional fields and MP_REACH_NLRI | `src/daemon.rs` | ✅ | `test_handle_update_mp_reach_announces_ipv4_route`, `test_handle_update_mp_unreach_withdraws_ipv4_route`, interop:gobgp |
| IPv4 unicast outbound: MP_REACH_NLRI (via `announced` field) + MP_UNREACH_NLRI with NEXT_HOP rewrite | `src/outbound.rs` | ✅ | `test_propagate_prefix_sends_update_for_new_route`, `test_propagate_prefix_sends_withdraw_when_route_removed`, interop:gobgp |
| IPv6 unicast inbound: MP_REACH_NLRI / MP_UNREACH_NLRI insert/withdraw into LocRib_v6 | `src/daemon.rs` | ✅ | `test_handle_update_mp_reach_ipv6_inserts_into_loc_rib_v6`, `test_handle_update_mp_unreach_ipv6_withdraws_route` |
| IPv6 unicast outbound: MP_REACH_NLRI with NEXT_HOP rewrite (eBGP); pass-through (iBGP) | `src/daemon.rs` | ✅ | `test_propagate_prefix_v6_ibgp_announces_route`, `test_propagate_prefix_v6_ebgp_with_local_ipv6_rewrites_nexthop` |
| Full-table dump on Established includes IPv6 routes | `src/daemon.rs` | ✅ | `test_on_established_sends_v6_full_table_dump` |
| Unknown AFI/SAFI: silently ignored (no session reset) | `src/daemon.rs` | ✅ | `test_handle_update_mp_unreach_non_ipv4_is_skipped` |

---

## RFC 4724 — End-of-RIB Marker, Graceful Restart Helper + Speaker Roles

**Owns:** EOR send/receive; GracefulRestart capability advertisement (helper role); stale-route
retention when a connected peer restarts uncleanly (speaker role).  
**Boundary:** FSM restart detection (R-bit) is in `pathvector-session`; the daemon owns the
per-family retention decision, deadline timer, and EOR-triggered prune.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4724

| Requirement | File | Status | Verified by |
|---|---|---|---|
| IPv4 EOR (minimum-length UPDATE) sent after full-table dump | `src/outbound.rs`, `src/daemon.rs` | ✅ | `test_on_established_empty_rib_sends_eor_only`, `test_on_established_sends_full_table_dump` |
| IPv6 EOR (empty MP_UNREACH_NLRI for IPv6 unicast) sent for v6-capable peers | `src/outbound.rs`, `src/daemon.rs` | ✅ | `test_on_established_ipv6_capable_peer_receives_both_eors` |
| EOR skipped when channel stalls (session will be torn down) | `src/daemon.rs` | ✅ | stall handling path in `on_established` |
| EOR receive-side: detect peer IPv4 EOR (empty UPDATE) and record it | `src/daemon.rs` | ✅ | `test_ipv4_eor_received_is_recorded`, `eor_ipv4_received_from_gobgp_is_recorded` |
| EOR receive-side: detect peer IPv6 EOR (empty MP_UNREACH_NLRI) and record it | `src/daemon.rs` | ✅ | `test_ipv6_eor_received_is_recorded` |
| EOR receive state cleared on session termination / re-establishment | `src/daemon.rs` | ✅ | `test_eor_state_cleared_on_termination`, `test_eor_state_cleared_on_re_establish` |
| EOR state exposed via management API (`eor_ipv4_received`, `eor_ipv6_received`) | `src/grpc.rs`, `proto/` | ✅ | `eor_ipv4_received_from_gobgp_is_recorded`, `eor_ipv4_received_persists_after_route_churn` |
| GracefulRestart capability advertised so peers send EOR | `src/daemon.rs` | ✅ | `eor_ipv4_received_from_gobgp_is_recorded` |
| §3 helper role: advertise `restart_time > 0` + forwarding-preserved families when `graceful_restart_time` is configured | `src/daemon.rs`, `src/config.rs` | ✅ | `test_build_local_capabilities_gr_enabled`, `test_build_local_capabilities_gr_disabled`, `test_build_local_capabilities_gr_clamps_at_4095` |
| §3 helper role: F-bit false when we are the restarting speaker (FIB was wiped on startup) | `src/daemon.rs` | ✅ | `test_build_local_capabilities_f_bit_false_when_restarting`, `test_build_local_capabilities_f_bit_true_when_stable` |
| §3 helper role: F-bit correctly encoded in OPEN wire bytes | `pathvector-session/src/message/open.rs` | ✅ | `test_gr_family_forwarding_preserved_roundtrip` |
| §3 R-bit set only within the restart window (`startup_instant.elapsed() < graceful_restart_time`) | `src/daemon.rs` — `SpawnConfig::capabilities()` | ✅ | `spawn_config_r_bit_set_within_restart_window`, `spawn_config_r_bit_cleared_after_restart_window` |
| §3 R-bit not set when `graceful_restart_time = 0` | `src/daemon.rs` | ✅ | `test_build_local_capabilities_r_bit_ignored_when_gr_disabled` |
| §4.2 MUST NOT: R-bit not set when re-establishing a session unless we restarted; F-bit reflects intact forwarding state — the set is replaced after every non-removal teardown, whether or not the event was coalesced (issue #148) | `src/daemon/mod.rs` — `handle_session_terminated` | ✅ | `reconnect_resends_role_and_gr_capabilities_via_set_capabilities`, `coalesced_teardown_refreshes_capabilities`, `coalesced_teardown_refreshes_capabilities_when_batch_ends_in_notification` |
| §3 peer's restart_time extracted from peer OPEN and stored in `gr_capable_peers` | `src/daemon.rs` | ✅ | `gr_capable_peer_is_recorded_on_established`, `gr_eor_only_peer_not_recorded` |
| §3 duplicate GR capabilities from peer: no panic (✅) but uses the **first** non-zero instance, not the **last** (❌) | `src/daemon.rs` | ⚠️ | `duplicate_gr_capabilities_do_not_panic_and_first_wins`, `zero_gr_then_nonzero_gr_uses_first_nonzero` — **corrected 2026-07-16 by `RFC_AUDIT.md`**: RFC 4724 §3 says "the receiver of the advertisement MUST ignore all but the **last** instance of the Graceful Restart Capability" — `peer.rs:383-402`'s `.find_map(...)` takes the first `GracefulRestart` capability with `restart_time > 0`, which is the opposite of what the RFC requires. The existing tests' own names ("first_wins") describe the current, non-compliant behavior, not RFC-correct behavior. Low real-world likelihood of a peer actually sending 2+ instances (the RFC calls it a sender violation), but the receiver-side handling is still backwards when it does happen. |
| §3 SHOULD — suppress GR capability advertisement if peer's restart_time = 0 | `src/daemon.rs` | ⚠️ | SHOULD only; we log a warning but still advertise — deferred to Phase 2 |
| GR capability roundtrip codec fidelity (arbitrary flags, time, families) | `pathvector-session/src/message/open.rs` | ✅ | `gr_capability_roundtrips` (proptest) |
| GR capability decoder: truncated input returns error, does not panic | `pathvector-session/src/message/open.rs` | ✅ | `gr_capability_truncated_input_does_not_panic` (proptest) |
| GR capability decoder: trailing family bytes are dropped, not an error | `pathvector-session/src/message/open.rs` | ✅ | `gr_capability_trailing_bytes_ignored` (proptest) |
| e2e: GoBGP holds routes during our restart window (blackhole use case) | `pathvector-e2e/tests/session.rs` | ✅ | `gr_helper_gobgp_holds_routes_during_restart_window` |
| e2e: peer GR restart_time visible via management API | `pathvector-e2e/tests/session.rs` | ✅ | `gr_capability_negotiated_peer_gr_restart_time_reflects_config` |
| §4.2 MUST: unclean termination of GR-capable peer retains routes in AdjRibIn/LocRib | `src/daemon.rs` | ✅ | `unclean_termination_of_gr_peer_retains_routes` |
| §4.2 MUST: NOTIFICATION-driven termination flushes immediately when RFC 8538 not in effect | `src/daemon.rs` | ✅ | `clean_termination_flushes_immediately` (see also RFC 8538 below) |
| §4.2 MUST: non-GR peer routes always flushed on unclean termination | `src/daemon.rs` | ✅ | `non_gr_peer_always_flushes_on_unclean_termination` |
| §4.2 MUST: per-family GR — only families listed in peer OPEN are retained | `src/daemon.rs` | ✅ | per-family `gr_v4`/`gr_v6` check in `on_terminated` |
| §4.2 MUST: routes not re-announced before peer EOR are pruned; re-announced routes kept | `src/daemon.rs` | ✅ | `eor_prunes_stale_routes_not_refreshed_by_peer` |
| §4.2 IPv6 EOR triggers pruning of stale IPv6 NLRIs | `src/daemon.rs` | ✅ | `prune_stale_nlri_v6` + IPv6 EOR branch |
| §4.2 MUST: GR window expiry without re-establishment flushes all stale routes | `src/daemon.rs` | ✅ | `gr_deadline_expiry_flushes_stale_routes` |
| §4.2 MUST: retained routes marked stale (`Staleness::GrStale`) — **and stale routes keep their ordinary preference** ("MUST NOT differentiate between stale and other routing information during forwarding"; RFC 9494 §1: "in conventional GR, route preference is not affected") | `src/daemon/gr.rs`, `pathvector-rib/src/adj_rib_in.rs`, `pathvector-rib/src/best_path.rs` | ✅ | `daemon::gr_preference_tests::conventional_gr_keeps_stale_higher_local_pref_route_selected`, `stale_marking_keeps_equally_preferred_route_selected`, `pathvector-rib` `best_path::tests::conventional_gr_*` + `prop_conventional_gr_staleness_never_changes_the_winner`. **Corrected 2026-11-23 (issue #68):** this row previously read "SHOULD: retained routes de-preferred in best-path so a fresh peer wins immediately", backed by tests asserting that a stale LOCAL_PREF-300 route lost to a fresh LOCAL_PREF-100 one. RFC 4724 has no such SHOULD; de-preferencing is RFC 9494 (LLGR) behavior, which is not implemented. |
| §4.2 + RFC 9494 §1: marking routes stale sends no UPDATE (conventional GR resolves the trade-off "in favor of not advertising"); staleness is never part of the advertised route | `pathvector-rib/src/outbound.rs` (`prepare_outbound{,_v6}` reset staleness) | ✅ | `daemon::gr_preference_tests::{conventional_gr_stale_marking_does_not_readvertise_when_an_alternative_exists, stale_marking_of_sole_route_sends_no_duplicate_update, stale_marking_of_sole_v6_route_sends_no_duplicate_update}`, `stale_mark_sends_no_update_to_established_observer`, `outbound::tests::test_prepare_outbound_never_carries_staleness`. Before issue #68, marking a selected route stale re-sent an identical UPDATE for it to every peer. |
| §4.2 MUST: re-announcement replaces the stale route; End-of-RIB removes the rest; Restart Time expiry falls back to the fresh alternative | `src/daemon/route.rs`, `src/daemon/gr.rs` | ✅ | `daemon::gr_preference_tests::{reannouncement_replaces_stale_route_and_end_of_rib_removes_the_rest, restart_time_expiry_falls_back_to_the_fresh_alternative}` |
| §4.2: retained is not eligible — stale marking re-imports each route through the same pipeline as arrival (ingress gate, BLACKHOLE agreement, import policy): policy-/ROV-/OTC-rejected routes stay out of the Loc-RIB, LOCAL_PREF / communities / next-hop rewrites / ingress OTC survive, a BLACKHOLE route stays a blackhole (RFC 4271 §9.1.1–§9.1.2, RFC 8538 §4.1, RFC 9234 §5). **Issue #82** (the originally reported rejected-route and LOCAL_PREF repros were already fixed on main by #139/#140; the BLACKHOLE-as-unicast half was not) | `src/daemon/gr.rs`, `src/daemon/import.rs`, `pathvector-rib/src/adj_rib_in.rs` (`mark_all_stale` no longer returns raw routes for re-insertion) | ✅ | `graceful_restart_does_not_admit_a_policy_rejected_route`, `graceful_restart_preserves_local_pref_set_by_import_policy`, `graceful_restart_keeps_otc_leak_rejection_and_ingress_otc_attachment`, `graceful_restart_keeps_rov_rejection`, `graceful_restart_never_turns_a_blackhole_route_into_unicast` (all IPv4 + IPv6) |
| §4.2: full lifecycle — drop (retain + mark stale, still exported), re-establish, refresh replaces, End-of-RIB sweeps the un-refreshed (Loc-RIB, FIB, peers told, null routes), expiry deletes the rest | `src/daemon/gr.rs`, `src/daemon/route.rs` | ✅ | `graceful_restart_lifecycle_retains_refreshes_and_sweeps`, `graceful_restart_retains_refreshes_and_sweeps_null_routes`, `graceful_restart_deadline_expiry_deletes_retained_routes` |
| §4.2: only families in the peer's GR capability are retained; the rest are flushed at once (Adj-RIB-In, Loc-RIB, FIB, other peers) — **fixed 2026-11-24**: previously only the Adj-RIB-In was cleared, so the family's Loc-RIB entries, FIB routes and advertisements lingered until the Restart Time | `src/daemon/peer.rs` (`flush_family_v4/v6`) | ✅ | `graceful_restart_flushes_families_the_peer_did_not_advertise` |
| e2e: unclean disconnect holds routes; window expiry flushes them | `pathvector-e2e/tests/graceful_restart_phase2.rs` | ✅ | `gr_phase2_routes_held_during_restart_window_then_flushed_on_expiry` |
| e2e: clean disconnect (NOTIFICATION) flushes routes immediately, no GR window | `pathvector-e2e/tests/graceful_restart_phase2.rs` | ✅ | `gr_phase2_clean_disconnect_flushes_routes_immediately` |
| e2e: peer restart with partial RIB — un-refreshed routes pruned on EOR | `pathvector-e2e/tests/graceful_restart_phase2.rs` | ✅ | `gr_phase2_eor_prunes_stale_routes_not_refreshed_by_peer` |
| §8.1 `connect_retry_time` configurable per-peer (TOML: `connect_retry_time`); defaults to 120 s | `src/config.rs`, `src/daemon.rs` | ✅ | `sidecar_round_trips_all_fields`; exercised by fast-retry harness in GR e2e tests |
| §4.1 MUST: Restarting Speaker defers its own route selection until EOR received from all GR-capable peers or a Selection_Deferral_Timer expires | `src/daemon/deferral.rs`, `src/config.rs` (`selection_deferral_time`), `src/outbound.rs` (`propagate_prefix`/`propagate_prefix_v6`'s `deferred` parameter) | ✅ | `daemon::deferral::tests::*`, `outbound::propagate_tests::test_propagate_prefix{,_v6}_deferred_*`, `daemon::selection_deferral_tests::*`. Scoped to **outbound-advertisement-only** deferral (Loc-RIB/FIB computation stays immediate), matching BIRD's real implementation rather than the RFC's literal "defer route selection" text — see `RFC_AUDIT.md`'s RFC 4724 §4.1 entry for the BIRD-source citation and the wait-set-membership design correction found during review. |
| e2e (2026-08-05, review of PR #50): the complete config → OPEN negotiation → real wire-encoded EOR → timer/wait-set → catch-up-dump path, not just `DaemonState`-direct unit tests | `pathvector-e2e/src/bin/mock_bgp_gr_peer.rs`, `pathvector-e2e/tests/selection_deferral.rs` | ✅ | `route_withheld_from_observer_until_deferral_timer_expires` (a GR-capable peer that never sends EOR: route reaches Loc-RIB immediately but is withheld from a separate observer peer until the Selection_Deferral_Timer force-releases and flushes it), `restart_time_zero_peer_blocks_release_until_its_own_eor_arrives` (a `restart_time == 0` EOR-only peer still blocks the wait-set until its real, delayed EOR arrives — release happens well before the deliberately much longer timer deadline, distinguishing the wait-set-satisfied path from the timer-expiry path) |
| e2e (2026-08-05, Codex follow-up round on the PR #50 gap closure): the wait-set is evaluated over the **full configured peer set**, not satisfied by any single peer's EOR — a single-source harness can't distinguish "correctly waits on every configured GR peer" from "incorrectly releases on the first EOR" | `pathvector-e2e/src/bin/mock_bgp_gr_peer.rs` (`eor-immediately` scenario), `pathvector-e2e/src/lib.rs` (`TwoSourceSelectionDeferralHarness`), `pathvector-e2e/tests/selection_deferral.rs` | ✅ | `fast_eor_from_one_source_does_not_release_wait_set_for_the_other` (two independent GR peers — one sends EOR immediately, the other withholds it forever — proves the fast peer's EOR is not mistaken for satisfying the slow peer's; release only happens once the Selection_Deferral_Timer itself expires) |

**Deferred:** §3 SHOULD: suppress GR capability when peer's restart_time = 0 (currently logged
as warning only). §4.2 (Receiving Speaker role) and §4.1 (Restarting Speaker's own deferred
route selection) requirements are both implemented and tested. The §5 FSM collision-override
for GR peers is also implemented — see `RFC_AUDIT.md`'s RFC 4724 section.

---

## RFC 8538 — Enhancements to BGP Graceful Restart

**Owns:** N-bit advertisement in the `GracefulRestart` capability; inspection of received
NOTIFICATIONs on termination to decide between immediate flush and GR window.  
**Boundary:** `TerminationReason::Notification` is produced by `pathvector-session`;
`on_terminated` in `pathvectord` applies the RFC 8538 decision logic.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc8538

| Requirement | File | Status | Verified by |
|---|---|---|---|
| §2 N-bit (0x04) set in `restart_flags` whenever `graceful_restart_time > 0` | `src/daemon/capabilities.rs` | ✅ | `build_local_capabilities_sets_n_bit_when_gr_enabled`, `build_local_capabilities_no_n_bit_when_gr_disabled` |
| §2 N-bit not set when `graceful_restart_time = 0` | `src/daemon/capabilities.rs` | ✅ | `build_local_capabilities_no_n_bit_when_gr_disabled` |
| §2 R-bit and N-bit set independently (R-bit only within restart window; N-bit always when GR enabled) | `src/daemon/capabilities.rs` | ✅ | `test_build_local_capabilities_gr_enabled`, `spawn_config_r_bit_set_within_restart_window` |
| §3 Peer N-bit extracted from peer OPEN `restart_flags` on Established | `src/daemon/peer.rs` — `on_established` | ✅ | `n_bit_peer_tracked_on_established`, `non_n_bit_peer_not_tracked_on_established` |
| §3 Peer N-bit tracking cleared when peer re-establishes without N-bit | `src/daemon/peer.rs` | ✅ | `n_bit_cleared_when_peer_re_establishes_without_it` |
| §3 Peer N-bit tracking cleared on `remove_peer` | `src/daemon/gr.rs` — `GracefulRestartState::remove_peer` | ✅ | `n_bit_cleared_on_remove_peer` |
| §4 Non-HardReset NOTIFICATION from N-capable peer → GR window (both sides must have N-bit) | `src/daemon/peer.rs` — `on_terminated` | ✅ | `notification_non_hard_reset_with_n_bit_enters_gr_window`, e2e: `gr_phase2_rfc8538_frr_notification_opens_gr_window` |
| §4 CEASE/HardReset (subcode 9) MUST trigger immediate flush even with N-bit | `src/daemon/peer.rs` — `on_terminated` | ✅ | `notification_hard_reset_always_flushes`, e2e: `gr_phase2_rfc8538_hard_reset_bypasses_gr_window` |
| §4 NOTIFICATION from peer without N-bit → flush immediately (RFC 4724 §4.2 preserved) | `src/daemon/peer.rs` — `on_terminated` | ✅ | `notification_without_peer_n_bit_flushes` |
| §4 WE must have N-bit for notification mode to engage; otherwise flush immediately | `src/daemon/peer.rs` — `on_terminated` | ✅ | `notification_flushes_when_local_daemon_has_no_gr` |
| `OperatorStop` (local-initiated teardown) always flushes immediately, regardless of N-bit | `src/daemon/peer.rs` — `on_terminated` | ✅ | `operator_stop_always_flushes` |

**Note on e2e peers:** GoBGP 4.6.0 sends `CEASE/Hard Reset` (subcode 9) on all shutdowns
when `notification-enabled = true` — used to validate the §5 Hard Reset bypass path.
FRR 8.x with `neighbor X graceful-restart-notification` sends `CEASE/Administrative-Shutdown`
(non-HardReset) on `docker stop` — used to validate the §4 positive path (GR window opens).

---

## RFC 7999 — BLACKHOLE Community (Discard Action)

**Owns:** Authorization and the discard action. A BLACKHOLE-tagged (0xFFFF029A) announcement
is honored only on a session that agreed to it, for prefixes the peer is authorized to
blackhole (RFC 7999 §3.3). An honored request is stored in Adj-RIB-In, never enters Loc-RIB
(so is never exported), and is programmed as a kernel null route (`RTN_BLACKHOLE`) via
rtnetlink; it is removed when the request is withdrawn, superseded, revoked or its session
ends. Relies on `is_blackhole()` from `pathvector-types` and `FibWrite::install_blackhole_v4/v6`
from `pathvector-sys`.  
**Boundary:** The `BLACKHOLE` constant lives in `pathvector-types`. Kernel programming lives in
`pathvector-sys`. Authorization lives here: `src/blackhole.rs` (`BlackholeScope`, the validated
config value), `src/daemon/blackhole.rs` (`BlackholeAgreement` → `AuthorizedBlackhole` →
`BlackholeBook`), `src/daemon/import.rs` (`ImportPipeline::classify`).  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc7999  
**Amendments checked (2026-11-24):** no RFC updates 7999; RFC 7606 (error handling for
malformed communities) and RFC 6811 (ROV, §3.3's "MUST ensure ... do not inadvertently block")
are the only cross-references.

**Design (issues #81, #82).** One pipeline — `ImportPipeline::classify_gated` — decides what a
received route *is*, and is used by UPDATE arrival, `set_import_default`, RPKI ROA-change
re-evaluation, Graceful Restart stale marking and (via `retire_routes` /
`BlackholeBook::release_peer`) cleanup:

| Outcome (`ImportDecision`) | Meaning | Loc-RIB | Null route |
|---|---|---|---|
| `Accepted(route)` | ordinary route, post-policy | candidate | — (a held claim by this peer is released) |
| `Blackhole(AuthorizedBlackhole)` | agreed session + prefix covered (RFC 7999 §3.3) | — (peer's unicast candidate evicted) | claimed |
| `Rejected` | ingress gate or import policy said no | — | released |
| `BlackholeDenied(why)` | BLACKHOLE-tagged, not agreed / out of scope / RFC 9234 leak | — | released |

`AuthorizedBlackhole` can only be minted by `BlackholeAgreement::authorize`, and
`BlackholeBook::claim` accepts nothing else, so a null route for an unauthorized prefix does not
type-check. The book records who owns which null route and is refcounted per prefix; `BlackholeChange`
changes (`Install` on the first holder, `Withdraw` on the last) are the only thing that reaches
the FIB port. `program_effects` (`src/daemon/fib.rs`) is the single place best-path and null-route
changes are translated into port calls.

**Why a denied request is not imported as unicast.** RFC 7999 §3.1 says the community "SHOULD be
ignored" by a network not using it, which could be read as "treat as an ordinary route". We
refuse instead: §3.3 says speakers "MUST only accept and honor" such announcements when both
conditions hold, and an ordinary Loc-RIB entry carrying 65535:666 could be selected, programmed
as a forwarding route and exported to other peers — spreading a blackhole beyond the one
session that agreed to it (§3.2). The route stays in Adj-RIB-In.

**ROV exception.** Origin validation is an import-policy term, and an authorized request is
classified *instead of* by the import policy, so RFC 6811 Invalid (a `/32` is longer than any
ROA `maxLength`) and `import_default = "reject"` cannot block it. The explicit scope takes ROV's
place. RFC 9234 §5 leak detection is the one ordinary import rule that still applies.

| Requirement | File | Status | Verified by |
|---|---|---|---|
| §3.3 cond. 2: honored only if the session agreed (`blackhole_authorized_prefixes`); default denied (§4) | `src/daemon/blackhole.rs`, `src/daemon/import.rs`, `src/config.rs` | ✅ | `reject_default_blackhole_announcement_has_no_fib_effect`, `agreement_is_per_session`, `unagreed_blackhole_is_denied_even_under_accept_all`, `configuration_becomes_the_session_agreement` |
| §3.3 cond. 1: prefix covered by an equal or shorter authorized prefix; /32 and /128 inside an authorized /24 or /48 | `src/blackhole.rs` | ✅ | `covers_is_equal_or_shorter_scope_prefix`, `blackholes_outside_the_authorized_scope_are_denied`, `authorized_host_blackholes_are_honored_under_reject_default_and_never_exported` (IPv4 + IPv6) |
| §3.3: origin validation must not block a legitimate blackhole | `src/daemon/import.rs` | ✅ | `authorized_blackholes_are_exempt_from_origin_validation` (control: the same host route untagged is ROV-rejected), `authorized_blackhole_is_exempt_from_import_policy` |
| RFC 9234 §5 leak is still ineligible | `src/daemon/blackhole.rs` | ✅ | `route_leak_blackhole_request_is_still_ineligible`, `leak_guard_still_applies_to_authorized_blackholes` |
| Never exported / never a unicast Loc-RIB candidate (§3.2), through arrival, re-evaluation and GR | `src/daemon/import.rs` | ✅ | `reevaluation_never_imports_a_blackhole_route_as_unicast`, `graceful_restart_never_turns_a_blackhole_route_into_unicast`, `accepted_blackholes_remain_blackholes_across_reevaluation`, model property `ipv{4,6}_pipeline_invariants` (no BLACKHOLE-tagged candidate) |
| Kernel null route programmed on announce, removed on withdraw / supersede | `src/daemon/route.rs`, `src/fib.rs` | ✅ | `blackhole_route_programs_kernel_null_route`, `explicit_withdrawal_removes_the_null_route`, `unicast_replacement_of_a_blackhole_removes_the_null_route`; e2e `authorized_ipv4_host_blackhole_is_installed_and_withdrawn`, `authorized_ipv6_host_blackhole_is_installed_withdrawn_and_scoped` (Docker/Linux) |
| Revocation / narrowing of the agreement re-evaluates and removes null routes — no stale kernel entry | `src/daemon/policy.rs` | ✅ | `revoking_or_narrowing_the_agreement_removes_null_routes_without_leaving_stale_ones`, `revocation_during_the_gr_window_removes_retained_null_routes` |
| One null route per prefix across peers; a denied peer's withdrawal removes nothing | `src/daemon/blackhole.rs` | ✅ | `null_route_is_shared_and_withdrawn_only_by_the_last_holder`, `releasing_a_blackhole_the_peer_never_held_is_a_noop` |
| A held null route is not overwritten by a unicast best-path change — from any caller: import, next-hop recomputation (`on_fib_change`), local origination; the Loc-RIB route is restored when the blackhole goes | `src/daemon/fib.rs`, `src/daemon/origination.rs` | ✅ | `unicast_best_path_changes_never_overwrite_a_held_null_route`, `next_hop_recovery_does_not_overwrite_a_held_null_route` (v4+v6), `originating_a_blackholed_prefix_does_not_overwrite_the_null_route`, `blackhole_withdrawal_restores_surviving_peer_unicast_route` |
| Session end / GR expiry / EOR sweep release the peer's null routes (IPv4 + IPv6) | `src/daemon/peer.rs`, `src/daemon/gr.rs` | ✅ | `clean_session_end_removes_the_peers_null_routes`, `graceful_restart_retains_refreshes_and_sweeps_null_routes`, `graceful_restart_expiry_removes_null_routes`, `blackhole_route_removed_for_non_gr_family_on_unclean_termination` |
| Re-evaluation equals fresh import; idempotent; book == authorized stored requests | `src/daemon/import.rs` | ✅ | proptests `ipv4_pipeline_invariants`, `ipv6_pipeline_invariants` |
| Not implemented: §3.2 "SHOULD add NO_ADVERTISE or NO_EXPORT" — moot, a blackhole is never exported at all | — | n/a | — |
| Not implemented: §3.3 "store all updates carrying BLACKHOLE for audit" beyond the Adj-RIB-In (BMP covers the long-term case) | — | ⚠️ | — |

**Known limitation — BLACKHOLE-to-unicast failover coalescing:** when the last blackhole for a
prefix is withdrawn and the Loc-RIB has a best path for it, `FibManager`'s coalescing map
receives `WithdrawBlackhole` immediately followed by `Install { gateway }`; the `Install`
overwrites the pending delete, and the kernel receives `RTM_NEWROUTE` with `NLM_F_REPLACE`
(`pathvector-sys` install path), which replaces the existing entry regardless of route type.
Unit-tested against `RecordingFib`; not yet exercised by a Linux e2e with a competing unicast.

**Not runnable on macOS:** the e2e tests above need Docker and a Linux kernel
(`CAP_NET_ADMIN` for `RTM_NEWROUTE`); they compile on macOS (`cargo check -p pathvector-e2e
--tests`) but were not run here. Revocation has no e2e: there is no runtime configuration
reload yet, so the agreement is fixed at `add_peer`.

---

## RFC 1997 — BGP Communities Attribute (Outbound Enforcement)

**Owns:** Enforcing the propagation restriction each well-known community
carries. The `Community` type and `is_no_advertise()`/`is_no_export()`/
`is_no_export_subconfed()` predicates live in `pathvector-types`; the
enforcement point — `pathvector_rib::outbound::is_export_suppressed()`,
called from `propagate_prefix`/`propagate_prefix_v6` right after export
policy evaluates a route as `Accept` — lives here and in `pathvector-rib`.  
**Boundary:** Community match/mutation policy conditions and actions live in
`pathvector-policy`. Wire encoding lives in `pathvector-session`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc1997

| Requirement | File | Status | Verified by |
|---|---|---|---|
| `NO_ADVERTISE`: "MUST NOT be advertised to other BGP peers" — suppressed for both iBGP and eBGP peers | `pathvector-rib/src/outbound.rs`, `src/outbound.rs` | ✅ | `test_propagate_prefix_no_advertise_suppresses_ebgp_announcement`, `test_propagate_prefix_no_advertise_suppresses_ibgp_announcement`, `test_propagate_prefix_v6_no_advertise_suppresses_ebgp_announcement` |
| `NO_EXPORT`: "MUST NOT be advertised outside a BGP confederation boundary" — suppressed for `External` peers, not `Internal`/`ConfedMember` | `pathvector-rib/src/outbound.rs`, `src/outbound.rs` | ✅ | `test_propagate_prefix_no_export_suppresses_ebgp_but_allows_ibgp`, `test_propagate_prefix_v6_no_export_suppresses_ebgp_but_allows_ibgp` |
| `NO_EXPORT_SUBCONFED`: "MUST NOT be advertised to external BGP peers (this includes peers in other members autonomous systems inside a BGP confederation)" — suppressed for `External` **and** `ConfedMember` peers, not `Internal` | `pathvector-rib/src/outbound.rs`, `src/outbound.rs` | ✅ | `test_propagate_prefix_no_export_subconfed_suppresses_ebgp_but_allows_ibgp` |
| A route already advertised is withdrawn once it starts carrying a suppressing community | `src/outbound.rs` | ✅ | `test_propagate_prefix_no_advertise_withdraws_previously_announced` |
| Suppression reflects communities *after* export policy runs, not the pre-policy Loc-RIB state — a policy-added well-known community suppresses; a policy-removed one lifts suppression | `src/outbound.rs` | ✅ | `test_propagate_prefix_export_policy_added_no_advertise_suppresses_announcement`, `test_propagate_prefix_export_policy_removes_no_export_allows_ebgp_announcement` |

**RFC 8642 (Policy Behavior for Well-Known BGP Communities) ordering note:**
raised by a PR #42 review comment — RFC 8642 (which updates RFC 1997)
confirms operators routinely add/remove/replace well-known communities via
export policy. `propagate_prefix`/`propagate_prefix_v6` call
`is_export_suppressed()` *after* `export_policy.evaluate(&mut route)` has
already mutated `route` in place, so the check inherently sees post-policy
communities — a `NO_ADVERTISE` added by a policy action suppresses the
announcement even if the Loc-RIB route never carried it, and a `NO_EXPORT`
present on the Loc-RIB route but removed by a policy action no longer
suppresses. This was already the natural consequence of the check's
placement, not a new code change; the two tests above make the ordering an
explicit, regression-guarded contract rather than an implicit accident.
See `pathvector-policy/RFC.md`'s RFC 1997 section for how `SetCommunities`
(replaces the entire list, well-known or not) relates to RFC 8642's
documentation requirement for the "set" directive.

**Confederation-boundary scoping note (resolved 2026-08-04):** RFC 1997
defines `NO_EXPORT`'s boundary as the confederation boundary, explicitly
noting "a stand-alone autonomous system that is not part of a confederation
should be considered a confederation itself." With RFC 5065 confederation
Member-AS support now implemented (see the RFC 5065 section below),
`is_export_suppressed()` correctly distinguishes the two cases:
`NO_EXPORT` blocks `External` peers only (a `ConfedMember` peer is, by
definition, still inside the confederation boundary); `NO_EXPORT_SUBCONFED`
blocks both `External` and `ConfedMember` peers.

---

## RFC 8212 — Default External BGP Route Propagation Without Policy

**Owns:** The default import/export policy when no policy is configured: reject all routes
from/to eBGP peers. Accept all routes from/to iBGP peers.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc8212

| Requirement | File | Status | Verified by |
|---|---|---|---|
| eBGP peers: reject all received routes when no import policy is configured | `src/daemon.rs` | ✅ | `test_daemon_state_new_ebgp_gets_reject_default_when_omitted`, `test_rfc8212_ebgp_ipv6_reject_without_policy` |
| eBGP peers: reject all outbound routes when no export policy is configured | `src/daemon.rs` | ✅ | `test_resolve_export_ebgp_omitted_defaults_to_reject`, `test_propagate_prefix_sends_withdraw_when_export_policy_rejects` |
| iBGP peers: accept all received routes when no import policy is configured | `src/daemon.rs` | ✅ | `test_resolve_import_ibgp_omitted_defaults_to_accept` |
| iBGP peers: accept all outbound routes when no export policy is configured | `src/daemon.rs` | ✅ | `test_resolve_export_ibgp_omitted_defaults_to_accept` |

---

## RFC 7607 — Codification of AS 0 Processing

**Owns:** Refusing AS 0 in configuration, rejecting a received route that
carries it, and never advertising it.  
**Boundary:** OPEN and received-attribute handling live in `pathvector-session`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc7607

| Requirement | File | Status | Verified by |
|---|---|---|---|
| AS 0 refused in `local_as`, `confederation_id`, `remote_as` when the config (or dynamic-peer sidecar) is read | `src/config.rs` | ✅ | `as_zero_is_refused_in_every_identity_field`, `non_zero_identities_parse`, `sidecar_entry_with_as_zero_is_skipped` |
| AS 0 and AS_TRANS (23456) rejected as `remote_as` over gRPC | `src/grpc.rs` `validate_remote_as` | ✅ | `test_add_peer_rejects_as_zero` |
| Received AS_PATH containing AS 0: treat-as-withdraw, older route removed | `src/daemon/ingress.rs` | ✅ | `ingress_drop_tests.rs`, `prohibited_replacement_removes_the_installed_v4_route` / `_v6_route` (wire → FSM → daemon) |
| Received AGGREGATOR with AS 0: attribute discarded, route kept | `pathvector-session` decoder | ✅ | `as_zero_aggregator_keeps_the_route_without_the_attribute` |
| §2: "MUST NOT originate or propagate": AS 0 in AS_PATH is not advertised (a previous advertisement is withdrawn); an AS 0 AGGREGATOR is left off; AS4_PATH / AS4_AGGREGATOR are derived from these | `src/egress.rs`, `src/outbound.rs` | ✅ | `as_zero_in_as_path_is_never_advertised`, `as_zero_aggregator_is_omitted_by_both_builders` |

---

## RFC 9774 — Deprecation of AS_SET and AS_CONFED_SET

**Owns:** Never advertising a set, and the daemon-side receive gate.  
**Boundary:** Wire receive handling lives in `pathvector-session`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc9774

| Requirement | File | Status | Verified by |
|---|---|---|---|
| §3: received sets (AS_PATH or AS4_PATH) are withdrawals: the older route leaves Adj-RIB-In, Loc-RIB, FIB and peers, and the UPDATE's own withdrawals still apply — IPv4 and IPv6 | `src/daemon/route.rs`, `src/daemon/ingress.rs` | ✅ | `prohibited_replacement_removes_the_installed_v4_route`, `prohibited_replacement_removes_the_installed_v6_route`, `daemon_gate_withdraws_a_set_route_handed_in_directly`, `as_sets_are_treat_as_withdraw` |
| §3: no advertised UPDATE contains a set, judged on the path as sent (an AS_CONFED_SET stripped toward an external peer does not block the route) | `src/egress.rs`, `src/outbound.rs` | ✅ | `sets_are_judged_on_the_path_that_would_be_sent`, `either_set_type_blocks_and_sequences_do_not`, `originated_route_with_a_set_is_not_advertised` |
| §3: operator exception for a transition period | — | ❌ | not offered (see `TODO.md`) |

---

## RFC 4456 — BGP Route Reflection

**Owns:** Route Reflector configuration, inbound attribute processing (ORIGINATOR_ID,
CLUSTER_LIST, loop detection), RR-aware iBGP split-horizon in the outbound decision, and
outbound inclusion of reflection attributes in UPDATE messages.  
**Boundary:** ORIGINATOR_ID / CLUSTER_LIST wire codec lives in `pathvector-session`.
Route struct fields for carrying the attributes live in `pathvector-rib`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4456

| Requirement | File | Status | Verified by |
|---|---|---|---|
| `is_rr_client` peer config flag + `cluster_id` daemon config | `src/config.rs` | ✅ | `test_config_rr_client_field_default_false` (config tests) |
| Loop detection: discard UPDATE if our `cluster_id` in CLUSTER_LIST (client peers) | `src/daemon.rs` | ✅ | `test_rr_loop_detection_discards_update` |
| Loop detection: discard UPDATE if our `cluster_id` in CLUSTER_LIST (non-client iBGP peers) | `src/daemon.rs` | ✅ | `test_rr_cluster_list_loop_detection_applies_to_non_client_ibgp` |
| Loop detection: discard UPDATE if ORIGINATOR_ID == local BGP ID | `src/daemon.rs` | ✅ | `test_rr_originator_id_loop_detection_discards_update` |
| ORIGINATOR_ID set to peer's BGP ID on first reflection (client) | `src/daemon.rs` | ✅ | `test_rr_originator_id_and_cluster_list_set_on_reflected_route` |
| ORIGINATOR_ID set to peer's BGP ID on first reflection (non-client iBGP) | `src/daemon.rs` | ✅ | `test_rr_non_client_ibgp_to_client_injects_rr_attrs` |
| cluster_id prepended to CLUSTER_LIST on each reflection | `src/daemon.rs` | ✅ | `test_rr_originator_id_and_cluster_list_set_on_reflected_route` |
| Client → all other clients: reflect (not back to originating client) | `src/daemon.rs` | ✅ | `test_rr_client_route_reflected_to_other_client` |
| Client → non-client iBGP peers: reflect | `src/daemon.rs` | ✅ | `test_rr_client_route_reflected_to_non_client_ibgp` |
| Non-client iBGP → clients: reflect with correct RR attributes | `src/daemon.rs` | ✅ | `test_rr_non_client_ibgp_route_reflected_to_client`, `test_rr_non_client_ibgp_to_client_injects_rr_attrs` |
| Non-client iBGP → non-client iBGP: blocked (standard split-horizon) | `src/daemon.rs` | ✅ | `test_rr_non_client_ibgp_to_non_client_ibgp_still_blocked` |
| ORIGINATOR_ID + CLUSTER_LIST included in outbound UPDATE attributes | `src/outbound.rs` | ✅ | `test_rr_originator_id_and_cluster_list_set_on_reflected_route` |
| ORIGINATOR_ID + CLUSTER_LIST stored on ingested routes as received, IPv4 **and IPv6** (the IPv6 path used to drop both, so reflected IPv6 routes left this RR without them) | `src/daemon/route.rs` (`handle_update`) | ✅ | `rr_tie_break_tests::{ipv6_reflected_routes_store_rr_attributes_and_select_by_originator_id, ipv6_route_reflected_to_another_client_carries_originator_id_and_cluster_list}` |
| §9 tie-breakers (ORIGINATOR_ID for step (f), then shorter CLUSTER_LIST before peer address) applied to ingested routes | `src/daemon/route.rs` → `pathvector-rib` `best_path` | ✅ | `rr_tie_break_tests::{reflected_routes_are_selected_by_originator_id_not_reflector_id, shorter_cluster_list_is_selected_before_peer_address}` |
| RFC 7606 §7.9 / §7.10: ORIGINATOR_ID / CLUSTER_LIST "received from an external neighbor ... SHALL be discarded using the approach of 'attribute discard'". Kept only from `Internal` peers. A `ConfedMember` peer is in "a different Autonomous System" (RFC 4271) and RFC 5065 grants no exception for these attributes, which matches the outbound stripping toward `ConfedMember` | `src/daemon/route.rs` (`handle_update`) | ✅ | `rr_tie_break_tests::{ebgp_originator_id_and_cluster_list_are_discarded, confed_member_originator_id_and_cluster_list_are_discarded}` |
| adj_ribs_out_v6 uses reflecting mode for all iBGP peers when acting as RR | `src/daemon.rs` | ✅ | `test_rr_v6_adj_rib_out_is_reflecting_for_ibgp_peer` |
| adj_ribs_out_v6 reflecting mode preserved after session reconnect | `src/daemon.rs` | ✅ | `test_rr_v6_adj_rib_out_reflecting_restored_after_reconnect` |
| IPv6 split-horizon: non-client iBGP → non-client iBGP blocked in propagation | `src/daemon.rs` | ✅ | `test_rr_v6_split_horizon_blocks_non_client_to_non_client` |
| IPv6 split-horizon: non-client iBGP → non-client iBGP blocked in full-table dump | `src/daemon.rs` | ✅ | `test_rr_v6_established_dump_applies_split_horizon` |
| §6 non-client → non-client exclusion applied on **every** send path (incremental, table dump, session loss, GR stale marking / End-of-RIB prune / deadline expiry, export-policy change), IPv4 and IPv6, including while the source's session is down (routes retained for GR) and for peers on IPv6 transport (issue #168) | `src/outbound.rs` `excluded_by_reflection`, called from `propagate_prefix` / `propagate_prefix_v6` | ✅ | `src/daemon/rr_split_horizon_tests.rs` |
| RFC 4271 §9.1.3: a destination the §6 rule excludes is sent a withdrawal for what it was previously advertised (a non-client's path replacing a client's as best) | `src/outbound.rs` | ✅ | `rr_split_horizon_tests::{update_taking_over_from_client_withdraws_v4_and_v6, session_loss_withdraws_when_non_client_takes_over_v4, gr_expiry_withdraws_when_non_client_takes_over_v4_and_v6, eor_prune_withdraws_when_non_client_takes_over_v4_and_v6}` |

---

## RFC 9003 — Extended BGP Administrative Shutdown Communication (Daemon Integration)

**Owns:** Reading `shutdown_message: Option<String>` from `PeerConfig`; sending the encoded
payload in `Cease/AdministrativeShutdown` NOTIFICATION during `RemovePeer`.  
**Boundary:** Wire encoding of the payload (1-byte length + UTF-8, max 128 bytes) lives in
`pathvector-session::message::notification::encode_shutdown_message`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc9003

| Requirement | File | Status | Verified by |
|---|---|---|---|
| `shutdown_message: Option<String>` in `PeerConfig` | `src/config.rs` | ✅ | `test_sidecar_round_trips_all_fields` |
| `RemovePeer` sends `Cease/AdministrativeShutdown` with encoded reason when configured | `src/daemon.rs` | ✅ | — |
| `RemovePeer` falls back to bare `Stop` when no message is configured | `src/daemon.rs` | ✅ | `remove_peer_without_shutdown_message_sends_stop` |

---

## RFC 4271 §8 — Connection Collision Coordination

**Owns:** The FSM-level decision of which session to keep when two peers simultaneously
open connections (collision detection and resolution). In pathvectord, this is delegated
to the `pathvector-session` transport layer via `SessionHandle`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4271#section-8

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Detect when both the local and remote side open a connection to each other | `pathvector-session/src/transport/mod.rs` | ✅ | `test_collision_in_open_confirm_peer_bgp_id_higher_rejects_incoming` (in `pathvector-session`) |
| Keep the connection initiated by the router with higher BGP Identifier | `pathvector-session/src/transport/mod.rs` | ❌ | **Corrected 2026-07-16 — this was wrong.** `handle_incoming_connection`'s `should_close_outbound = local_bgp_id > peer_id` is inverted: it closes *our own* outbound connection when *our* ID is higher, and keeps it when *our* ID is lower — the opposite of RFC 4271 §6.8, which says to retain the connection initiated by the higher-ID speaker. `test_collision_in_open_confirm_peer_bgp_id_higher_rejects_incoming`'s own scenario (peer ID higher) asserts the session reaches `Established` over the *outbound* connection — i.e. it locks in the inverted behavior as if it were correct, which is why this went uncaught. See `RFC_AUDIT.md` §6.8 for the full derivation. |
| Send NOTIFICATION Cease / Connection Collision Resolution on dropped connection | `pathvector-session/src/fsm/mod.rs` | ❌ | None — corrected 2026-07-16 by `RFC_AUDIT.md` §6.8; the previous ✅ here was never backed by a test (see the `—` that used to be in this cell) and was wrong. Both `on_open_sent` and `on_open_confirm`'s `CollisionDetected` arms only emit `StopHoldTimer`/`StopKeepaliveTimer`/`CloseTcpConnection` — no `SendMessage` of any kind |
| RFC 4724 §5: when GR capability (≥1 AFI/SAFI) was negotiated for an Established session, a new incoming connection (Event 16/17) must be treated as peer restart — retain routes, drop the *old* connection, move to Connect — not rejected as an ordinary collision | `pathvector-session/src/transport/mod.rs` | ✅ | Fixed 2026-07-16 (`fix/rfc4271-collision-resolution`, `TODO.md` #17). `handle_incoming_connection`'s `State::Established` arm now checks GR-negotiated status and retains routes/drops the old connection/moves to Connect for GR peers instead of rejecting. See `RFC_AUDIT.md`'s RFC 4724 §5 entry. |

---

## RFC 4486 §4 — Maximum Number of Prefixes (Daemon Integration)

**Owns:** Per-AFI Adj-RIB-In size checking after each UPDATE; sending
`CEASE/MaximumNumberOfPrefixesReached`; keeping the session down afterwards, or starting it
again after `max_prefixes_restart` seconds. RFC 4271 §6.7 and RFC 4486 §4 require only the
Cease: whether and when to start again is local policy (RFC 4271 §8.1.1
`AllowAutomaticStart`, `IdleHoldTimer`).  
**Boundary:** The `CeaseError::MaximumNumberOfPrefixesReached` subcode constant and NOTIFICATION
wire encoding live in `pathvector-session`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4486#section-4

| Requirement | File | Status | Verified by |
|---|---|---|---|
| `max_prefixes_v4` / `max_prefixes_v6` / `max_prefixes_restart` in `PeerConfig` | `src/config.rs` | ✅ | `test_sidecar_round_trips_all_fields` |
| After each UPDATE, check IPv4 Adj-RIB-In against `max_prefixes_v4` | `src/daemon/route.rs` | ✅ | `cease_when_limit_exceeded` |
| After each UPDATE, check IPv6 Adj-RIB-In against `max_prefixes_v6` | `src/daemon/route.rs` | ✅ | `cease_when_v6_limit_exceeded` |
| Either limit firing causes CEASE independently | `src/daemon/route.rs` | ✅ | `cease_when_v6_limit_exceeded` |
| No CEASE when count is at or below limit | `src/daemon/route.rs` | ✅ | `no_cease_at_exact_limit`, `no_cease_when_under_limit` |
| Send `CEASE/MaximumNumberOfPrefixesReached` when limit exceeded | `src/daemon/route.rs` | ✅ | `cease_when_limit_exceeded` |
| Set idle-hold deadline when `max_prefixes_restart > 0` | `src/daemon/route.rs` | ✅ | `idle_hold_inserted_when_restart_configured` |
| Absent or zero `max_prefixes_restart`: no idle-hold; the peer is latched down | `src/daemon/route.rs` | ✅ | `no_idle_hold_without_restart` |
| A latched session neither redials nor accepts a connection (RFC 4271 §8.2.2 Idle) | `src/daemon/mod.rs` | ✅ | `max_prefix_without_restart_time_stays_down`, `max_prefix_with_zero_restart_time_stays_down` |
| Another reset queued for the same peer does not undo the latch | `src/daemon/mod.rs` | ✅ | `stalled_reset_does_not_undo_the_latch_first_event_path`, `stalled_reset_does_not_undo_the_latch_drain_loop_path` |
| Removing the peer completes while it is held down, so it can be added again | `src/daemon/peer.rs` | ✅ | `removing_and_adding_the_peer_clears_the_latch`, `removing_a_peer_cancels_its_pending_restart` |
| Positive N: session started N seconds after the CEASE, independently of `connect_retry_time` (RFC 4271 §8.1.3 `IdleHoldTimer_Expires`) | `src/daemon/mod.rs` | ✅ | `max_prefix_restart_shorter_than_connect_retry`, `max_prefix_restart_longer_than_connect_retry` |
| Do not register a session that reaches Established while held down; stop it with CEASE/Connection Rejected | `src/daemon/mod.rs` | ✅ | `event_loop_idle_hold_blocks_reconnect` |
| Same via the coalesced drain loop | `src/daemon/mod.rs` | ✅ | `event_loop_idle_hold_blocks_reconnect_in_drain_loop`, `idle_hold_reconnect_is_stopped_when_batch_ends_in_notification` |
| Ignore UPDATEs from a session refused during idle-hold, or otherwise unregistered (RFC 4271 §9) | `src/daemon/route.rs` | ✅ | `update_behind_rejected_established_is_ignored`, `coalesced_update_behind_rejected_established_is_ignored`, `update_from_rejected_session_does_not_rearm_idle_hold`, `update_from_unregistered_session_is_ignored` |
| Clear idle-hold deadline when timer expires (event loop) | `src/daemon/mod.rs` | ✅ | `event_loop_idle_hold_timer_clears_expired_deadline` |
| `add_peer` populates `peer_max_prefixes_v4/v6` + `peer_max_prefixes_restart` | `src/daemon/peer.rs` | ✅ | `add_peer_populates_max_prefix_maps` |
| `remove_peer` clears all max-prefix maps | `src/daemon/peer.rs` | ✅ | `remove_peer_clears_max_prefix_maps` |
| No limit enforced when `max_prefixes_v4`/`v6` is not configured | `src/daemon/route.rs` | ✅ | `no_limit_when_unconfigured` |
| LocRib reverts correctly when over-limit peer displaces an existing best path | `src/daemon/mod.rs` | ✅ | `displaced_best_path_reverts_after_termination` |

**Clearing a latched peer** (no `max_prefixes_restart`): restart the daemon, which reads the
peer's limits from the config again, or `RemovePeer` then `AddPeer`. A peer re-added that way has
only the settings `AddPeer` carries, which do not include a prefix limit, until the daemon
restarts. `AddPeer` on its own and `SoftReset` do not clear it. The latch is held in memory only.

**Deferred:**
- No operator action restarts a latched peer while keeping its limits, short of restarting the
  daemon.
- A peer that floods the same table after each restart is reset again every
  `max_prefixes_restart` seconds; there is no upper bound on the number of retries.

---

## RFC 9234 — Route Leak Prevention Using Roles in UPDATE and OPEN Messages

**Owns:** `PeerConfig.role` config; threading the configured `Role` into each
session's OPEN capabilities (including on reconnect, mirroring how the GR R-bit
survives reconnects); installing `pathvector-policy`'s OTC terms into each peer's
import/export policy with the corrected role-mapping; extracting/storing the
`ONLY_TO_CUSTOMER` attribute on ingress and re-emitting it on egress; exposing
configured/negotiated Role via gRPC and the CLI.  
**Boundary:** Wire format and role-pair OPEN validation are in `pathvector-session`.
OTC condition/action logic is in `pathvector-policy`. OTC storage on `Route<A>` is
in `pathvector-rib`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc9234

| Requirement | File | Status | Verified by |
|---|---|---|---|
| `PeerConfig.role: Option<PeerRole>`, TOML `role = "provider"/"rs"/"rs_client"/"customer"/"peer"` | `src/config.rs` | ✅ | `sidecar_round_trips_all_fields` |
| `Role` capability included in OPEN when `role` configured; omitted (non-strict default) otherwise | `src/daemon/capabilities.rs` | ✅ | `test_build_local_capabilities_includes_role_when_configured`, `test_build_local_capabilities_omits_role_when_none` |
| Role capability rebuilt per-session-spawn, including on reconnect (mirrors the GR R-bit lesson) | `src/daemon/mod.rs` | ✅ | `spawn_config_capabilities_includes_role_when_configured` (unit-level); `reconnect_resends_role_and_gr_capabilities_via_set_capabilities` (event-loop-level, also covers the pre-existing GR R-bit reconnect path) |
| OTC ingress terms (leak-reject + attach-if-absent) installed per the corrected role mapping | `src/daemon/mod.rs` `install_otc_import_term` | ✅ | `test_install_otc_terms_counts_per_role` (all 5 roles) |
| OTC egress terms (propagation-block + attach-if-absent) installed per the corrected role mapping | `src/daemon/mod.rs` `install_otc_export_term` | ✅ | `test_install_otc_terms_counts_per_role` (all 5 roles) |
| No OTC terms installed when `role` is unconfigured (non-strict default) | `src/daemon/mod.rs` | ✅ | `test_no_role_configured_installs_no_otc_terms` |
| Per-role route-level accept/reject/attach behaviour, all 5 roles, both static and dynamic peers | `src/daemon/mod.rs`, `src/daemon/peer.rs` | ✅ | `test_provider_role_rejects_route_leaked_with_otc_from_customer`, `test_provider_role_accepts_clean_route_without_attaching_otc`, `test_customer_role_attaches_peer_asn_on_ingress`, `test_route_server_role_rejects_leak_accepts_clean_without_attach`, `test_rs_client_role_attaches_peer_asn_on_ingress`, `test_peer_role_rejects_route_with_mismatched_otc_asn`, `test_peer_role_accepts_and_preserves_matching_otc`, `test_peer_role_egress_blocks_leaked_route_and_attaches_clean_one`, `add_peer_with_role_installs_otc_terms_and_peer_roles` |
| Full leak-prevention scenario across three peers (mirrors the 2019 Verizon/Allegheny/Cloudflare incident shape) | `src/daemon/mod.rs` | ✅ | `test_route_leak_prevented_across_two_provider_peers` |
| `peer_roles`/`remove_peer` lifecycle keeps Role config consistent across dynamic add/remove | `src/daemon/peer.rs` | ✅ | `add_peer_with_role_installs_otc_terms_and_peer_roles`, `remove_peer_clears_peer_roles` |
| Ingress: `PathAttribute::OnlyToCustomer` extracted into `Route.otc`, both v4 and v6 | `src/daemon/route.rs` | ✅ | `test_ipv6_ingress_otc_extraction_and_leak_rejection` (v6); the route-leak tests above (v4) |
| Egress: `Route.otc` re-emitted as `PathAttribute::OnlyToCustomer`, both v4 and v6 | `src/outbound.rs` | ✅ | `test_route_leak_prevented_across_two_provider_peers` (asserts the wire attribute) |
| OTC egress terms (propagation-block + attach-if-absent) actually enforced for IPv6, not just IPv4 — `propagate_prefix_v6` now evaluates `export_policies_v6` the same way `propagate_prefix` evaluates `export_policies` | `src/outbound.rs`, `src/daemon/mod.rs`, `src/daemon/policy.rs` | ✅ | `test_ipv6_egress_otc_block_and_attach` |
| Configured/negotiated Role exposed via gRPC `PeerState.configured_role`/`negotiated_role` | `src/grpc.rs` | ✅ | `test_build_peer_state_includes_configured_and_negotiated_role`, `test_build_peer_state_role_absent_by_default` |
| Real e2e proof: a route pre-carrying OTC from a peer configured `role = "provider"` is rejected; a clean route is accepted | `pathvector-e2e/tests/role.rs` | ✅ | `leaked_route_is_rejected_clean_route_is_accepted` |
| `set_import_default`/`set_export_default` (gRPC `PolicyService`) preserve installed OTC terms | `src/daemon/policy.rs`, `pathvector-policy/src/term.rs` `Policy::set_default` | ✅ | `test_set_import_and_export_default_preserve_otc_terms` (OTC); `test_set_import_default_preserves_rpki_rov_term` (same code path, the pre-existing RFC 6811 exposure) |
| Role/OTC application is gated on `is_ebgp` — never applied to an iBGP peer even if `role` is misconfigured, both static and dynamic peers | `src/daemon/mod.rs` `effective_role`, `src/daemon/peer.rs` | ✅ | `test_effective_role_none_when_unconfigured`, `test_effective_role_returns_role_for_ebgp_peer`, `test_effective_role_none_for_ibgp_peer_even_when_configured` (the helper itself); `test_role_ignored_for_ibgp_peer`, `add_peer_ignores_role_for_ibgp_peer` (downstream effect, static and dynamic peers) |

**Deferred:**
- Strict mode (reject when only one side advertises Role) — the RFC makes this
  optional and non-default; tracked as a non-blocking follow-up in `TODO.md`.
- The e2e proof uses a custom mock BGP peer (`pathvector-e2e/src/bin/mock_bgp_peer.rs`)
  rather than FRR. FRR 8.4.4 (the version pinned in `Dockerfile.frr`) does fully
  support RFC 9234 (`neighbor <addr> local-role <role>`, confirmed directly against
  the built test image), but a well-behaved, RFC-9234-conformant router will never
  produce a genuine leak by construction — role-pair validation at OPEN time makes
  it structurally impossible for two correctly configured routers to leak between
  each other. Reproducing a real leak over the wire requires a peer willing to send
  one on purpose, which is what the mock peer is for.

**Correctness re-verification (2026-07-02):** independently re-checked the OTC
ingress/egress role mapping against the RFC 9234 datatracker text directly (not
from memory of this feature's own earlier development) — confirmed correct,
including the Peer role's symmetric handling (ingress-attach, egress-attach-if-
absent, and egress-block-if-present all apply simultaneously to a Peer session).
Also ran both `pathvector-fuzz` targets that decode the grown `Capability`/
`PathAttribute` enums (`session_framing`, `session_message`) for 60s each
(~10M executions apiece) — clean, no crashes. This was called for in the original
implementation plan but not actually executed until this reflection pass.

**Two real bugs found and fixed in this same pass (2026-07-02):**
1. `set_import_default`/`set_export_default` used to fully replace the peer's
   `Policy`, silently discarding installed OTC terms (and, it turns out, the
   pre-existing RFC 6811 ROV term too — same code path) with no warning. Proved
   with a throwaway reproduction before fixing: term count dropped from 1 to 0
   after a single `set_import_default` call. Fixed by adding
   `Policy::set_default` (changes only the default action) and using it instead
   of `Policy::new(action)` in both handlers. See `pathvector-rpki/RFC.md`'s
   RFC 6811 section for the shared ROV-side writeup.
2. Role/OTC application had no eBGP guard, despite the plan's own Non-goals
   section calling for one — confirmed by direct code inspection (no
   `is_ebgp`/`PeerType::External` check anywhere near the `role` handling).
   An operator who set `role` on an iBGP peer would get `Capability::Role` sent
   in OPEN and OTC leak-detection applied to iBGP-learned routes, which could
   incorrectly reject a route that legitimately carries OTC from its original
   eBGP ingestion elsewhere in the network. Fixed by gating `role` on `is_ebgp`.

**Performance:** re-benchmarked `pathvector-rib`'s `outbound_pipeline` suite
against a clean `main` checkout in an isolated `git worktree` (the most directly
relevant benchmark, since it exercises the OTC egress-attribute emission added
by this feature) — all six size/scenario combinations landed within ~1-2% of
`main`, i.e. noise, not a regression. `select_best` and `loc_rib_insert` showed
the same "no change"/"within noise" result via Criterion's own before/after
comparison. Matches the architectural expectation: OTC storage is lazily
allocated on `RareAttrs` and adds only O(1) checks on the hot path.

---

## RFC 5065 — AS Confederations for BGP (Full Member-AS Support)

**Owns:** Confederation config schema (`DaemonConfig.confederation_id`,
`PeerConfig.confederation_member`, `effective_confederation_member`);
threading `confederation_member`/`confederation_id` into every session
classification and spawn call site; `public_as` resolution
(`confederation_id.unwrap_or(local_as)`) and threading it through the
outbound pipeline; the MED/RR-metadata attribute-stripping split for
`ConfedMember` peers; the RFC 5065 §5 malformed-AS_PATH import checks and
the extended (confederation-ID-aware) loop detection; gRPC/proto surface.  
**Boundary:** AS_PATH segment types, `strip_confed_segments()`,
`prepend_confed()`, and `PeerType::ConfedMember` live in `pathvector-types`.
Best-path preference (`ConfedMember` ties with `Internal`), split-horizon,
and `prepare_outbound`/`prepare_outbound_v6`'s per-peer-type AS_PATH/
NEXT_HOP/LOCAL_PREF transform live in `pathvector-rib`. The **authoritative**
`PeerType` classification for live Established sessions is in
`pathvector-session`'s FSM (`FsmConfig.confederation_member` /
`Fsm::build_session_info`) — see that crate's `RFC.md`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc5065

Prior to this work, RFC 5065 support was pass-through/interop only:
correctly stripping confederation segments from routes relayed from someone
else's confederation, but with zero representation for *originating or
relaying as an actual confederation Member-AS* — `PeerType` had only
`Internal`/`External`/`Local`, and there was no confederation config schema
at all. Flagged as "significant, architectural, not a quick fix" by
`RFC_AUDIT.md`'s 2026-07-16 audit-the-audit finding and filed as its own
initiative (`TODO.md` task #128) rather than folded into the smaller RFC
4271/9234/1997 fixes shipped earlier. Full Member-AS support shipped
2026-08-04 (`feature/rfc5065-confederation-member-support`).

| Requirement | File | Status | Verified by |
|---|---|---|---|
| `DaemonConfig.confederation_id` / `PeerConfig.confederation_member` config schema | `src/config.rs` | ✅ | `sidecar_round_trips_all_fields` |
| `config_peer_type` classifies `ConfedMember` when `confed_member` is set and AS numbers differ; `local_as == remote_as` still wins first (matches BIRD's `is_internal` precedence) | `src/daemon/mod.rs` | ✅ | `test_config_peer_type_confed_member`, `test_config_peer_type_same_as_wins_over_confed_member`, `prop_config_peer_type_internal_iff_equal` |
| `effective_confederation_member` degrades gracefully (warns, treats as plain eBGP) when `confederation_member` is set but `confederation_id` isn't — mirrors `effective_role`'s shape | `src/daemon/mod.rs` | ✅ | (exercised via `add_peer`/session-spawn call sites; no separate config-abort path exists in this codebase for per-peer misconfiguration, matching `effective_role`'s precedent) |
| `confederation_id` threaded through `RibSnapshot`/`DaemonState::new`/`SpawnConfig`/`SessionConfig` to every classification and session-spawn site — the critical fix for the two-place `PeerType` classification gap (FSM for live sessions, `config_peer_type` for pre-Established/post-disconnect) | `src/daemon/mod.rs`, `src/daemon/peer.rs`, `src/daemon/capabilities.rs` | ✅ | Full 726-test suite; see `pathvector-session/RFC.md` for the FSM half |
| `public_as` (`confederation_id.unwrap_or(local_as)`, but see the correction below — resolved via `effective_session_as`, not a bare `unwrap_or`, once `PeerType` is known) resolved once per propagation site and threaded through `propagate_prefix`/`propagate_prefix_v6` to `prepare_outbound`/`prepare_outbound_v6` | `src/outbound.rs`, `src/daemon/route.rs`, `src/daemon/policy.rs`, `src/daemon/deferral.rs`, `src/daemon/peer.rs`, `src/daemon/gr.rs` | ✅ | Full test suite (mechanical threading, same shape as the `deferred`-parameter PR) |
| OPEN message `my_as` and the `FourByteAsn` capability also carry `public_as` (Confederation Identifier for `External` peers, Member-AS Number for `Internal`/`ConfedMember`) — RFC 5065 §4 covers *all* transactions with a peer, not just AS_PATH | `src/daemon/mod.rs` (`effective_session_as`, static spawn loop, reconnect capability refresh), `src/daemon/peer.rs` (dynamic `AddPeer`), `src/daemon/capabilities.rs` (`SpawnConfig::capabilities`), `pathvector-session/src/fsm/mod.rs` (`FsmConfig::public_as`, `make_open`) | ✅ | `test_effective_session_as_external_uses_confederation_id`, `test_effective_session_as_internal_uses_member_as`, `test_effective_session_as_confed_member_uses_member_as`, `test_effective_session_as_external_falls_back_to_local_as_when_unconfigured`, `pathvector-session`'s `test_sent_open_uses_public_as_not_local_as` |
| MED not stripped for `ConfedMember` (RFC 5065 §5.2); ORIGINATOR_ID/CLUSTER_LIST still stripped for `ConfedMember` (deliberate — RR clusters are scoped to a single AS's internal topology; RFC 5065 is silent on the interaction, and letting RR metadata cross a Member-AS boundary risks cluster-ID collisions without serving RR's loop-prevention purpose) | `src/outbound.rs` `route_to_attributes`/`route_v6_to_attributes` | ✅ | `test_route_v6_to_attributes_ibgp_preserves_med`-style coverage extended to the `strip_med`/`strip_rr_metadata` split |
| AS4_PATH excludes AS_CONFED_SEQUENCE/AS_CONFED_SET (RFC 6793 §§3, 4.2.2) even though the downgraded wire AS_PATH correctly keeps them | `src/outbound.rs` `route_to_attributes`/`route_v6_to_attributes` (`pathvector_types::As4Path`) | ✅ | `as4_path_excludes_confed_segments_for_two_byte_peer`, `test_route_v6_to_attributes_as4path_excludes_confed_segments`, `as4_path_content_in_both_builders` |
| e2e (2026-08-05, round 2, Codex follow-up review): the above was unit-tested only — nothing proved the real wire codec on both ends produces the expected split: a confed segment surviving the AS_PATH value toward a fellow `ConfedMember` peer (RFC 5065 §5.3) while AS4_PATH excludes it entirely | `pathvector-e2e/src/bin/mock_bgp_as4path_peer.rs`, `pathvector-e2e/tests/as4path_confed.rs` | ✅ | `as4_path_excludes_confed_segment_while_wire_as_path_keeps_it` (a four-byte-ASN-capable confed-source sends AS_PATH = [AS_CONFED_SEQUENCE, 4-byte ASN]; a fellow confed-member observer that hasn't negotiated `FourByteAsn` decodes pathvectord's re-advertised UPDATE and confirms the confed segment survives alongside AS_TRANS substitution, while AS4_PATH carries the real ASN with the confed segment excluded). **Scope correction (2026-08-05, PR #52 review):** the observer's `two-byte-observer` role name refers to capability negotiation only — pathvectord's AS_PATH encoder always writes 4 bytes per ASN regardless of negotiation (encode-side downgrade is implemented for AGGREGATOR only), so this test proves the logical AS_TRANS/AS4_PATH-split decision, not genuine two-octet-per-ASN wire interop; that remains an open gap (`TODO.md`) |
| LOCAL_PREF accept guard widened from `Internal`-only to `Internal \| ConfedMember` (RFC 4271 §5.1.5's confederation exception, RFC 5065 §5.2) | `src/daemon/route.rs` | ✅ | `test_local_pref_honored_from_confed_member_peer` |
| Loop detection (RFC 4271 §9.1.2) extended to also check the confederation ID, not just `local_as` (RFC 5065 §4) | `src/daemon/route.rs` | ✅ | `test_as_path_loop_detection_drops_confederation_id_in_path`, `test_as_path_loop_detection_confederation_id_absent_does_not_block` |
| e2e (2026-08-05, round 2, Codex follow-up review): the above was unit-tested only | `pathvector-e2e/src/bin/mock_bgp_fault_peer.rs` (`confederation-id-loop` scenario), `pathvector-e2e/tests/fault_injection.rs` | ✅ | `confederation_id_in_as_path_is_treated_as_loop_and_dropped` (a plain `External` peer sends a well-formed UPDATE whose AS_PATH contains the confederation identifier; asserts the route never reaches Loc-RIB while the session stays Established) |
| RFC 5065 §5 condition 1: confed segment from an `External` peer is malformed — treat-as-withdraw | `src/daemon/route.rs` | ✅ | `test_malformed_as_path_confed_segment_from_external_peer_is_treat_as_withdraw` |
| RFC 5065 §5 condition 2: an AS_PATH from a `ConfedMember` peer whose first segment is not `AS_CONFED_SEQUENCE` is malformed — treat-as-withdraw. Covers empty AS_PATH too (no exemption: an empty path has no first segment, so it cannot be `AS_CONFED_SEQUENCE`) | `src/daemon/route.rs` | ✅ | `test_malformed_as_path_confed_member_peer_missing_confed_sequence_is_treat_as_withdraw`, `test_malformed_as_path_empty_from_confed_member_peer_is_treat_as_withdraw`, `test_malformed_as_path_confed_member_peer_with_confed_sequence_first_is_accepted` (negative case) |
| Both §5 conditions are treat-as-withdraw, not session-reset (RFC 7606 §3(e)) | `src/daemon/route.rs` | ✅ | `test_malformed_as_path_confed_conditions_are_treat_as_withdraw_not_session_reset` |
| Exception: when the UPDATE has no reachable NLRI at all, treat-as-withdraw would be a no-op — RFC 7606 §5.2 requires session reset instead in that case | `src/daemon/route.rs` | ✅ | `test_malformed_as_path_confed_segment_from_external_peer_no_nlri_resets_session`, `test_malformed_as_path_confed_member_peer_missing_confed_sequence_no_nlri_resets_session`, `test_malformed_as_path_empty_from_confed_member_peer_no_nlri_resets_session` |
| gRPC `proto_peer_type()` includes `ConfedMember` (compiler-forced exhaustive match) | `src/grpc.rs` | ✅ | (compile-time guarantee) |

**End-to-end coverage (2026-08-05, `pathvector-e2e`):** the requirement
table above is entirely `pathvectord`-unit-test-level — hand-built
`UpdateMessage`/`Route` structs, no real wire codec, no real peer
implementation. Two gaps that unit tests structurally cannot close:

- Real confederation interop, not just unit-level correctness:
  `ConfederationHarness` (`pathvector-e2e/src/lib.rs`) stands up
  pathvectord as a real confederation Member-AS against FRR (configured
  as a fellow Member-AS via FRR's own `bgp confederation identifier`/
  `bgp confederation peers` directives — FRR is confederation-aware,
  unlike a plain eBGP speaker, and its own outbound AS_PATH handling was
  never something this project's tests controlled) and a genuinely
  external GoBGP peer. `pathvector-e2e/tests/confederation.rs`'s tests
  confirm both sessions establish with the correct visible AS (the
  external GoBGP peer's config expects the confederation identifier in
  pathvectord's OPEN, not the Member-AS — a `public_as` regression would
  make that specific session fail to establish while the FRR session
  still came up fine), a route from FRR crosses to the external peer with
  confed segments fully stripped (checked against real `gobgp global rib`
  output), a route from the external peer crosses to FRR with a
  prepended confederation segment (checked against real FRR `vtysh show
  bgp` output, which renders confederation segments in parentheses and
  marks the route `confed-external`), and — added 2026-08-05, round 2,
  Codex follow-up review, since the above only covered announcements —
  a withdrawal from the external peer removes the route from FRR's own
  RIB (`withdrawal_from_external_peer_propagates_to_confed_member`, via
  `ConfederationHarness::external_withdraw()` and the new
  `wait_for_frr_rib_withdrawn` helper) — and, added 2026-08-05, round 2,
  Codex follow-up review, the confederation-specific attribute exceptions
  themselves: LOCAL_PREF survives relay from FRR into pathvectord's own
  Loc-RIB (`local_pref_survives_relay_from_confed_member`, RFC 5065 §5.2),
  NEXT_HOP toward FRR is left unchanged by default
  (extended into `route_from_external_relayed_to_confed_member_prepends_confed_sequence`,
  RFC 5065 §5.1), MED from the external peer survives relay to FRR
  (`med_is_preserved_when_relayed_to_confed_member`, via new
  `ConfederationHarness::external_announce_with_med` — RFC 5065 §5.2,
  unlike pathvectord's own convention of stripping MED for plain
  `External` peers), and `NO_EXPORT_SUBCONFED` suppresses advertisement to
  FRR (`no_export_subconfed_suppresses_advertisement_to_confed_member`,
  via new `ConfederationHarness::external_announce_no_export_subconfed` —
  RFC 1997, unlike plain `NO_EXPORT` which does not block a fellow
  Member-AS peer).
- RFC 5065 §5's two malformed-AS_PATH conditions over a real BGP session:
  `mock_bgp_fault_peer` gained `rfc5065-confed-segment-with-nlri` and
  `rfc5065-confed-segment-no-nlri` scenarios (`pathvector-e2e/src/bin/
  mock_bgp_fault_peer.rs`), exercised by
  `rfc5065_confed_segment_with_nlri_treated_as_withdraw_session_stays_up`
  and `rfc5065_confed_segment_no_nlri_resets_session`
  (`pathvector-e2e/tests/fault_injection.rs`) — proving the real wire
  codec on both ends produces the same treat-as-withdraw/session-reset
  split the unit tests assert on hand-built messages.
- e2e (2026-08-05, round 2, Codex review): condition 1 above only
  exercised an ordinary `External` peer — condition 2 (a peer pathvectord
  actually classifies as `ConfedMember`, sending an AS_PATH that doesn't
  lead with `AS_CONFED_SEQUENCE`) had no e2e coverage at all.
  `mock_bgp_fault_peer` gained
  `rfc5065-confed-member-wrong-first-segment-with-nlri` and
  `rfc5065-confed-member-wrong-first-segment-no-nlri` scenarios, exercised
  by `FaultInjectionHarness::new_confed_member` (pathvectord configured
  with `confederation_id`, the fault peer marked `confederation_member =
  true`) via
  `rfc5065_confed_member_wrong_first_segment_with_nlri_treated_as_withdraw_session_stays_up`
  and `rfc5065_confed_member_wrong_first_segment_no_nlri_resets_session`.

Real-teeth verified: the confederation interop test was run with
`strip_confed_segments()` temporarily disabled in `pathvector-rib`'s
`prepare_outbound` (confirmed it failed — the malformed export never
even reached the external GoBGP peer, since GoBGP itself won't accept
it), restored and reran green; the two fault-injection scenarios were
verified the same way against `daemon/route.rs`'s RFC 5065 §5 check. The
four confederation-attribute assertions (2026-08-05) were each real-teeth
verified independently: LOCAL_PREF by narrowing `daemon/route.rs`'s accept
guard back to `Internal`-only; NEXT_HOP by removing the `next_hop_self`
gate on `prepare_outbound`'s `ConfedMember` branch so it always rewrote;
MED by widening `outbound.rs`'s `strip_med` to include `ConfedMember`; and
`NO_EXPORT_SUBCONFED` by narrowing `is_export_suppressed`'s check back to
`External`-only — each confirmed to fail for the stated reason, then
reverted to a clean (`git diff --stat`-empty) state and reconfirmed green.
The MED assertion needed a second iteration: an initial bare
`route.contains("50")` false-positived against the broken code because
the external peer's own AS number (65099) contains "50" as a substring;
fixed by matching the literal `"metric 50"` FRR renders for the actual
attribute, re-verified RED then GREEN against the corrected assertion.

**Treat-as-withdraw, not session-reset, for RFC 5065 §5 (corrected
2026-08-05 after external code review; see `CHANGELOG.md`):** this section
originally implemented literal session-reset, reasoning that RFC 5065 §5's
citation of RFC 4271 §6.3 was unamended because RFC 5065 is absent from RFC
7606's formal "Updates: 1997, 4271, 4360, 4456, 4760, 5543, 5701, 6368"
header. That reasoning was wrong: RFC 7606 §3 states "This specification
amends Section 6.3 of [RFC4271]" and its §3(e) says "Treat-as-withdraw MUST
be used for the cases that specify a session reset and involve any of the
attributes ORIGIN, AS_PATH, NEXT_HOP, MULTI_EXIT_DISC, or LOCAL_PREF." RFC
5065 §5 doesn't hard-code session-reset itself — it delegates to "the
procedures of [BGP-4], Section 6.3" by reference, and both of its
conditions specify a session reset involving AS_PATH. Since RFC 7606 §3
directly rewrites the referenced procedure's text (not merely the
originating RFC 4271 document), the amendment applies via the reference,
regardless of whether RFC 5065 itself appears in the formal "Updates:"
list — that list names documents whose own text RFC 7606 edits, not every
document that cites RFC 4271 §6.3. The one exception, RFC 7606 §3(j)/§5.2
(session reset when NLRI wasn't successfully parsed), is preserved two
ways: gating the RFC 5065 §5 checks on `notification.is_none()` so an
already-decided §5.2 session-reset (from the earlier missing-mandatory-
attribute block) wins, **and** — found in a follow-up review pass
2026-08-05 — branching *within* the RFC 5065 §5 checks themselves on
`has_reachable_nlri_on_wire`. Treat-as-withdraw only has meaning when
there is announced NLRI to drain; on an UPDATE with a malformed AS_PATH
but zero reachable NLRI, draining an empty list is a silent no-op, which
is exactly the case RFC 7606 §5.2 forbids ("if any path attribute errors
are encountered in such an UPDATE message and if any encountered error
specifies an error-handling approach other than 'attribute discard', then
the 'session reset' approach MUST be used") — so that branch sends a
`MalformedAsPath` NOTIFICATION instead. BIRD's real source (fetched
directly) implements both conditions as withdraw-only, which — now
correctly derived from RFC text rather than from the formal Updates-list
heuristic alone — matches this project's implementation too (for the
has-reachable-NLRI case; BIRD's handling of the no-NLRI edge case was not
separately verified).

**Critical finding caught during planning, not implementation (see
`pathvector-session/RFC.md`'s RFC 5065 section for the fix):** `PeerType`
is classified in two independent places workspace-wide — this crate's
`config_peer_type` (authoritative only for the pre-Established/
post-disconnect windows) and `pathvector-session`'s FSM
(`Fsm::build_session_info`, authoritative for every live Established
session). A design that extended only `config_peer_type` would have
shipped a daemon that classifies correctly while a peer is disconnected
and silently misclassifies every live confederation-member session as
plain `External` — caught by a dedicated design-review pass before any
code was written, independently re-verified by reading `fsm/mod.rs`
directly.

**Deferred:** RFC 5065 §4.1's "MAY include/prepend more than one
instance... controlled via local configuration" (SHOULD-level
repeat-prepend-count knob) — no existing precedent anywhere in this
codebase for a "prepend N times" config field. Filed as a follow-up
`TODO.md` item rather than folded into this already-large feature. Also
deferred: the gRPC `AddPeer` RPC does not yet expose a
`confederation_member` field, so dynamically-added peers cannot be
configured as confederation members (static config only, for now).

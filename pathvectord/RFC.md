# RFC Requirements — pathvectord

This crate owns the **daemon integration layer**: the gRPC service, session orchestration,
Update-Send Process, attribute transforms, and policy defaults. It is the only crate in
the workspace that ties all other crates together.

**Status key:** ✅ Implemented and tested | ⚠️ Partial — see notes | ❌ Not started  
**Verified by key:** `test_name` — unit test | `interop:x` — GoBGP interop | `e2e:x` — end-to-end test | `—` — no automated verification

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
| Withdrawal sent to all peers when a best path is removed | `src/daemon.rs` | ✅ | `test_propagate_prefix_sends_withdraw_when_route_removed`, `test_on_terminated_propagates_withdraw_to_other_established_peers` |
| eBGP split-horizon: route received from eBGP peer not re-advertised back to that peer | `src/daemon.rs` | ✅ | `test_propagate_prefix_ebgp_source_peer_not_readvertised` |
| iBGP split-horizon: route received from iBGP peer not re-advertised to other iBGP peers | `src/daemon.rs` | ✅ | `test_propagate_prefix_ibgp_split_horizon_no_send`, `test_propagate_prefix_ibgp_split_horizon_eviction_sends_withdraw` |
| NLRI batching: announcements with same path attributes packed into fewest UPDATEs within `max_len` | `src/outbound.rs` | ✅ | `test_flush_same_attrs_batched_into_one_message`, `test_flush_splits_when_exceeding_max_len`, `test_flush_withdrawal_split_delivers_all_nlris` |
| Announcement groups with distinct path attributes go into separate UPDATEs | `src/outbound.rs` | ✅ | `test_flush_different_attrs_two_messages` |
| Withdrawals sent before announcements; withdrawal list packed within `max_len` | `src/outbound.rs` | ✅ | `test_flush_withdrawals_before_announces`, `test_flush_withdrawal_split_delivers_all_nlris` |

---

## RFC 4271 §9.2.1.1 — Minimum Route Advertisement Interval (MRAI)

**Owns:** eBGP MRAI enforcement: suppressing repeated announcements of the same NLRI
within a 30-second window to dampen UPDATE bursts toward eBGP peers. Withdrawals bypass
MRAI unconditionally.  
**Boundary:** Wire serialisation lives in `pathvector-session`. AdjRibOut is updated
before the MRAI gate, so the RIB reflects correct state even while wire transmission is
deferred.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4271#section-9.2.1.1

| Requirement | File | Status | Verified by |
|---|---|---|---|
| 30 s MRAI for eBGP peers; repeated announcement within window suppressed | `src/daemon.rs` | ✅ | `mrai_suppresses_ebgp_announcement_within_window` |
| Announcement allowed after MRAI window elapses | `src/daemon.rs` | ✅ | `mrai_passes_after_window_elapsed` |
| Suppressed NLRIs tracked in `mrai_pending`; flushed by half-MRAI timer | `src/daemon.rs` | ✅ | `flush_mrai_pending_clears_elapsed_pending`, `has_mrai_pending_true_when_set_nonempty` |
| Per-NLRI readiness: only NLRIs whose individual window elapsed are flushed | `src/daemon.rs` | ✅ | `flush_mrai_pending_clears_elapsed_pending` |
| Withdrawals bypass MRAI (RFC 4271 §9.2.1.1 explicit exemption) | `src/daemon.rs` | ✅ | `mrai_withdrawal_bypasses_suppression` |
| iBGP MRAI (SHOULD ≥5 s per RFC 4271 §9.2.1.1) | — | ❌ | — |

**Deferred:** iBGP MRAI. The RFC says SHOULD ≥5 s for iBGP; current implementation applies
no MRAI to iBGP peers. Low operational impact at typical iBGP topologies; deferred until
route dampening is implemented (both share the `Clock` trait prerequisite).

---

## RFC 6793 — Four-Octet AS Number Capability (Outbound Encoding)

**Owns:** Outbound AS_PATH encoding for 2-byte-only peers: substituting 4-byte ASNs with
AS_TRANS (23456) and appending the original path as AS4_PATH (type 17, flags 0xC0 =
optional+transitive) so downstream 4-byte-capable routers can reconstruct the full path.  
**Boundary:** `Asn::TRANS` constant and `AsPath::downgrade_for_two_byte_peer()` live in
`pathvector-types`. Inbound AS4_PATH merging (receiving from 2-byte peers) is owned by
`pathvector-session`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc6793#section-4

| Requirement | File | Status | Verified by |
|---|---|---|---|
| 4-byte ASNs replaced by AS_TRANS in wire AS_PATH for 2-byte-only peers | `src/outbound.rs` | ✅ | `four_byte_asn_to_two_byte_peer_inserts_trans_and_as4_path` |
| Original 4-byte ASNs preserved in AS4_PATH attribute for 2-byte-only peers | `src/outbound.rs` | ✅ | `four_byte_asn_to_two_byte_peer_inserts_trans_and_as4_path`, `all_four_byte_asns_to_two_byte_peer_full_trans_substitution` |
| No AS_TRANS / AS4_PATH for 4-byte-capable peers | `src/outbound.rs` | ✅ | `four_byte_asn_to_four_byte_peer_no_trans_no_as4_path` |
| No AS4_PATH when all ASNs fit in 2 bytes (no substitution occurred) | `src/outbound.rs` | ✅ | `two_byte_asns_to_two_byte_peer_no_trans_no_as4_path` |
| AS4_PATH appears as last attribute (2-byte speakers can skip unknown optional attributes) | `src/outbound.rs` | ✅ | `as4_path_is_last_attribute_for_two_byte_peer` |
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
| §3 peer's restart_time extracted from peer OPEN and stored in `gr_capable_peers` | `src/daemon.rs` | ✅ | `gr_capable_peer_is_recorded_on_established`, `gr_eor_only_peer_not_recorded` |
| §3 duplicate GR capabilities from peer handled without panic (first non-zero wins) | `src/daemon.rs` | ✅ | `duplicate_gr_capabilities_do_not_panic_and_first_wins`, `zero_gr_then_nonzero_gr_uses_first_nonzero` |
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
| §4.2 SHOULD: stale route marking — retained routes de-preferred in best-path so a fresh peer wins immediately | `src/daemon.rs`, `pathvector-rib/src/best_path.rs`, `pathvector-rib/src/adj_rib_in.rs` | ✅ | `stale_marking_lets_fresh_peer_win_immediately`, `stale_loses_to_non_stale_before_all_other_criteria` |
| e2e: unclean disconnect holds routes; window expiry flushes them | `pathvector-e2e/tests/graceful_restart_phase2.rs` | ✅ | `gr_phase2_routes_held_during_restart_window_then_flushed_on_expiry` |
| e2e: clean disconnect (NOTIFICATION) flushes routes immediately, no GR window | `pathvector-e2e/tests/graceful_restart_phase2.rs` | ✅ | `gr_phase2_clean_disconnect_flushes_routes_immediately` |
| e2e: peer restart with partial RIB — un-refreshed routes pruned on EOR | `pathvector-e2e/tests/graceful_restart_phase2.rs` | ✅ | `gr_phase2_eor_prunes_stale_routes_not_refreshed_by_peer` |
| §8.1 `connect_retry_time` configurable per-peer (TOML: `connect_retry_time`); defaults to 120 s | `src/config.rs`, `src/daemon.rs` | ✅ | `sidecar_round_trips_all_fields`; exercised by fast-retry harness in GR e2e tests |

**Deferred:** §3 SHOULD: suppress GR capability when peer's restart_time = 0 (currently logged
as warning only). All §4.2 requirements now implemented and e2e verified.

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
| §4 Non-HardReset NOTIFICATION from N-capable peer → GR window (both sides must have N-bit) | `src/daemon/peer.rs` — `on_terminated` | ✅ | `notification_non_hard_reset_with_n_bit_enters_gr_window` |
| §4 CEASE/HardReset (subcode 9) MUST trigger immediate flush even with N-bit | `src/daemon/peer.rs` — `on_terminated` | ✅ | `notification_hard_reset_always_flushes` |
| §4 NOTIFICATION from peer without N-bit → flush immediately (RFC 4724 §4.2 preserved) | `src/daemon/peer.rs` — `on_terminated` | ✅ | `notification_without_peer_n_bit_flushes` |
| §4 WE must have N-bit for notification mode to engage; otherwise flush immediately | `src/daemon/peer.rs` — `on_terminated` | ✅ | `notification_flushes_when_local_daemon_has_no_gr` |
| `OperatorStop` (local-initiated teardown) always flushes immediately, regardless of N-bit | `src/daemon/peer.rs` — `on_terminated` | ✅ | `operator_stop_always_flushes` |

**Deferred:** e2e test with a GoBGP peer that supports the N-bit (requires GoBGP config for RFC 8538 mode). Unit coverage is complete.

---

## RFC 7999 — BLACKHOLE Community (Discard Action)

**Owns:** The discard action: when a received UPDATE contains BLACKHOLE community
(0xFFFF029A), the route is stored in Adj-RIB-In but bypasses Loc-RIB and outbound
advertisement, and a kernel null route (`RTN_BLACKHOLE`) is programmed via rtnetlink.
On withdrawal, the kernel null route is removed. Relies on `is_blackhole()` from
`pathvector-types`, `BlackholeCondition` from `pathvector-policy`, and
`FibWrite::install_blackhole_v4/v6` from `pathvector-sys`.  
**Boundary:** The `BLACKHOLE` constant lives in `pathvector-types`. The policy condition
lives in `pathvector-policy`. Kernel programming lives in `pathvector-sys`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc7999

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Route with BLACKHOLE community stored in Adj-RIB-In but not installed in Loc-RIB | `src/daemon/route.rs` | ✅ | `blackhole_route_not_in_loc_rib` |
| BLACKHOLE route not advertised to peers | `src/daemon/route.rs` | ✅ | `blackhole_route_not_in_loc_rib` (LocRib empty → nothing propagated) |
| Kernel null route (`RTN_BLACKHOLE`) programmed on announce | `src/daemon/route.rs`, `src/fib.rs` | ✅ | `blackhole_route_programs_kernel_null_route` |
| Kernel null route removed on withdrawal | `src/daemon/route.rs`, `src/fib.rs` | ✅ | `blackhole_route_withdrawal_removes_kernel_null_route` |
| BLACKHOLE routes for non-GR address families withdrawn on unclean peer termination | `src/daemon/peer.rs` | ✅ | `blackhole_route_removed_for_non_gr_family_on_unclean_termination` |
| Surviving unicast best path re-installed after BLACKHOLE withdrawal | `src/daemon/route.rs` | ✅ | `blackhole_withdrawal_restores_surviving_peer_unicast_route` |

**Known limitation — BLACKHOLE-to-unicast failover coalescing:** when a BLACKHOLE route is
withdrawn and a competing unicast best path exists in Loc-RIB for the same prefix, the
FibManager coalescing map receives `WithdrawBlackhole` immediately followed by
`Install { gateway }`. Because the map keeps only the latest desired state per prefix, the
`Install` overwrites `WithdrawBlackhole` — the explicit `RTN_BLACKHOLE` kernel delete is
skipped, and the kernel receives `RTM_NEWROUTE` (unicast) while the null route may still be
present. In practice this works because `RTM_NEWROUTE` with `NLM_F_REPLACE` replaces the
existing entry regardless of route type, but this code path has not been exercised by a
multi-peer end-to-end test. If you operate a topology where a peer simultaneously
originates both a BLACKHOLE and a unicast for the same prefix, verify this behavior in
your environment.

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

## RFC 4456 — BGP Route Reflection

**Owns:** Route Reflector configuration, inbound attribute processing (ORIGINATOR_ID,
CLUSTER_LIST, loop detection), RR-aware iBGP split-horizon in the propagation loop, and
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
| adj_ribs_out_v6 uses reflecting mode for all iBGP peers when acting as RR | `src/daemon.rs` | ✅ | `test_rr_v6_adj_rib_out_is_reflecting_for_ibgp_peer` |
| adj_ribs_out_v6 reflecting mode preserved after session reconnect | `src/daemon.rs` | ✅ | `test_rr_v6_adj_rib_out_reflecting_restored_after_reconnect` |
| IPv6 split-horizon: non-client iBGP → non-client iBGP blocked in propagation | `src/daemon.rs` | ✅ | `test_rr_v6_split_horizon_blocks_non_client_to_non_client` |
| IPv6 split-horizon: non-client iBGP → non-client iBGP blocked in full-table dump | `src/daemon.rs` | ✅ | `test_rr_v6_established_dump_applies_split_horizon` |

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
| Keep the connection initiated by the router with higher BGP Identifier | `pathvector-session/src/transport/mod.rs` | ✅ | `test_collision_in_open_confirm_peer_bgp_id_higher_rejects_incoming` (in `pathvector-session`) |
| Send NOTIFICATION Cease / Connection Collision Resolution on dropped connection | `pathvector-session/src/transport/mod.rs` | ✅ | — |

---

## RFC 4486 §4 — Maximum Number of Prefixes (Daemon Integration)

**Owns:** Per-AFI Adj-RIB-In size checking after each UPDATE; sending
`CEASE/MaximumNumberOfPrefixesReached`; enforcing an idle-hold period before the peer
may reconnect.  
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
| No idle-hold when `max_prefixes_restart` is absent or zero | `src/daemon/route.rs` | ✅ | `no_idle_hold_without_restart` |
| Block `SessionEvent::Established` during idle-hold; send Stop | `src/daemon/mod.rs` | ✅ | `event_loop_idle_hold_blocks_reconnect` |
| Block reconnect during idle-hold via coalesced drain loop | `src/daemon/mod.rs` | ✅ | `event_loop_idle_hold_blocks_reconnect_in_drain_loop` |
| Clear idle-hold deadline when timer expires (event loop) | `src/daemon/mod.rs` | ✅ | `event_loop_idle_hold_timer_clears_expired_deadline` |
| `add_peer` populates `peer_max_prefixes_v4/v6` + `peer_max_prefixes_restart` | `src/daemon/peer.rs` | ✅ | `add_peer_populates_max_prefix_maps` |
| `remove_peer` clears all max-prefix maps | `src/daemon/peer.rs` | ✅ | `remove_peer_clears_max_prefix_maps` |
| No limit enforced when `max_prefixes_v4`/`v6` is not configured | `src/daemon/route.rs` | ✅ | `no_limit_when_unconfigured` |
| LocRib reverts correctly when over-limit peer displaces an existing best path | `src/daemon/mod.rs` | ✅ | `displaced_best_path_reverts_after_termination` |

**Deferred:**
- RFC 4486 §4 does not specify behaviour when the peer reconnects after the idle-hold
  expires and immediately re-floods the same table. pathvectord will CEASE again —
  this is correct but can produce rapid reconnect loops. Operators should size
  `max_prefixes_restart` to allow time for the peer's operator to intervene.

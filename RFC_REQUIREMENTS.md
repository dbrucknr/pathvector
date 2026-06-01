# BGP RFC Requirements

Tracks every RFC that pathvector sets out to implement, the concrete
requirements it imposes, which module owns each requirement, and the current
implementation status.

**Status key**
- ✅ Implemented and tested
- ⚠️ Partial — see notes
- ❌ Not started

**Verified by key**
- `test_name` — unit test that would fail if this requirement broke
- `proptest` — property-based test providing randomised coverage
- `interop: test_name` — integration test using real TCP sockets / a real BGP peer
- `—` — no automated verification; a test must be written

A ✅ with `—` in "Verified by" means the code exists but the correctness claim
is unprotected. Treat it the same as ⚠️ for test-coverage purposes.

---

## RFC 4271 — A Border Gateway Protocol 4 (BGP-4)

The core protocol. Every crate is shaped by it.

### §4 — Message Formats

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| 16-byte all-ones marker in every message header | `pathvector-session/src/message/header.rs` | ✅ | `test_encode_decode_header_roundtrip`, `test_header_marker_is_correct`, `test_encode_sets_all_ff_marker` |
| Marker validation — reject messages with a corrupt marker | `pathvector-session/src/message/header.rs` | ✅ | `test_decode_header_invalid_marker`, `test_decode_corrupt_marker_is_error`, `test_decode_rejects_bad_marker` |
| 2-byte length field (min 19, max 4096) | `pathvector-session/src/message/header.rs` | ✅ | `test_decode_header_length_too_small`, `test_decode_header_length_too_large`, `test_decode_length_too_small_is_error`, `test_decode_length_too_large_is_error` |
| 1-byte type field (OPEN=1, UPDATE=2, NOTIFICATION=3, KEEPALIVE=4) | `pathvector-session/src/message/header.rs` | ✅ | `test_decode_header_keepalive`, `test_decode_header_unknown_type` |
| OPEN: version=4, my_as, hold_time, bgp_id, optional parameters | `pathvector-session/src/message/open.rs` | ✅ | `test_minimal_open_roundtrip`, `test_open_with_capabilities_roundtrip`, `test_minimal_open_encoded_length` |
| OPEN: reject version ≠ 4 with NOTIFICATION | `pathvector-session/src/message/open.rs` | ✅ | `test_unsupported_version_rejected`, `test_unsupported_version_in_open_sends_notification` |
| OPEN: reject hold_time values of 1 or 2 (must be 0 or ≥ 3) | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_unacceptable_hold_time_sends_notification` |
| OPEN: reject bad BGP identifier | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_bad_bgp_id_sends_notification` |
| OPEN: reject mismatched peer AS | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_bad_peer_as_sends_notification` |
| UPDATE: withdrawn NLRI length + withdrawn NLRIs | `pathvector-session/src/message/update.rs` | ✅ | `test_withdrawal_only_roundtrip`, `test_empty_update_roundtrip` |
| UPDATE: total path attribute length + path attributes | `pathvector-session/src/message/update.rs` | ✅ | `test_announcement_with_core_attributes` |
| UPDATE: NLRI (announced prefixes) | `pathvector-session/src/message/update.rs` | ✅ | `test_announcement_with_core_attributes` |
| NLRI variable-length prefix encoding (only significant bytes on wire) | `pathvector-session/src/message/update.rs` | ✅ | `test_nlri_variable_length_encoding`, `test_invalid_ipv4_nlri_prefix_too_long`, `test_invalid_ipv6_nlri_prefix_too_long` |
| NOTIFICATION: error code + subcode + optional data | `pathvector-session/src/message/notification.rs` | ✅ | `test_hold_timer_expired_roundtrip`, `test_cease_admin_shutdown_roundtrip`, `test_encoded_length` |
| NOTIFICATION error code 1 — Message Header Error (subcodes 1–3) | `pathvector-session/src/message/notification.rs` | ✅ | `test_msg_header_error_roundtrips` |
| NOTIFICATION error code 2 — OPEN Message Error (subcodes 1–7) | `pathvector-session/src/message/notification.rs` | ✅ | `test_open_msg_error_roundtrips` |
| NOTIFICATION error code 3 — UPDATE Message Error (subcodes 1–11) | `pathvector-session/src/message/notification.rs` | ✅ | `test_update_msg_error_all_variants_roundtrip` |
| NOTIFICATION error code 4 — Hold Timer Expired | `pathvector-session/src/message/notification.rs` | ✅ | `test_hold_timer_expired_roundtrip` |
| NOTIFICATION error code 5 — Finite State Machine Error | `pathvector-session/src/message/notification.rs` | ✅ | `test_fsm_error_roundtrip` |
| Unknown NOTIFICATION codes preserved without corruption | `pathvector-session/src/message/notification.rs` | ✅ | `test_unknown_code_preserved` |
| KEEPALIVE: header only, no body | `pathvector-session/src/message/mod.rs` | ✅ | `test_keepalive_roundtrip`, `test_keepalive_is_19_bytes`, `test_encode_keepalive_produces_19_bytes` |
| KEEPALIVE with unexpected body bytes is an error | `pathvector-session/src/message/mod.rs` | ✅ | `test_keepalive_with_extra_body_is_error` |

### §5 — Path Attributes

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| ORIGIN (type 1, well-known mandatory): IGP=0, EGP=1, INCOMPLETE=2 | `pathvector-types/src/attr.rs` | ✅ | `test_origin_values`, `test_origin_from_u8`, `test_origin_ordering` |
| ORIGIN: invalid value rejected | `pathvector-session/src/message/update.rs` | ✅ | `test_invalid_origin_rejected` |
| AS_PATH (type 2, well-known mandatory): AS_SET(1) and AS_SEQUENCE(2) segments | `pathvector-types/src/aspath.rs` | ✅ | `test_aspath_from_sequence`, `test_aspath_display_mixed`, `test_as_path_with_set_roundtrip` |
| AS_PATH: truncated ASN in segment is an error | `pathvector-session/src/message/update.rs` | ✅ | `test_truncated_asn_in_as_path_is_error` |
| AS_PATH: unknown segment type is an error | `pathvector-session/src/message/update.rs` | ✅ | `test_unknown_as_path_segment_type_is_error` |
| AS_PATH prepend inserts own ASN at front of first AS_SEQUENCE | `pathvector-types/src/aspath.rs` | ✅ | `test_aspath_prepend_to_sequence` |
| AS_PATH prepend creates new AS_SEQUENCE when first segment is AS_SET | `pathvector-types/src/aspath.rs` | ✅ | `test_aspath_prepend_to_set_creates_new_segment` |
| AS_PATH prepend creates new AS_SEQUENCE when existing sequence is full (255 entries) | `pathvector-types/src/aspath.rs` | ✅ | `test_aspath_prepend_overflow_creates_new_segment` |
| NEXT_HOP (type 3, well-known mandatory for IPv4 unicast) | `pathvector-types/src/attr.rs` | ✅ | `test_next_hop_v4`, `test_next_hop_too_short_is_error` |
| MULTI_EXIT_DISC / MED (type 4, optional non-transitive) | `pathvector-types/src/attr.rs` | ✅ | `test_med_ordering`, `test_med_too_short_is_error` |
| LOCAL_PREF (type 5, well-known discretionary, iBGP only) | `pathvector-types/src/attr.rs` | ✅ | `test_local_pref_ordering`, `test_local_pref_default`, `test_local_pref_too_short_is_error` |
| ATOMIC_AGGREGATE (type 6, well-known discretionary, flag only) | `pathvector-types/src/attr.rs` | ✅ | `test_atomic_aggregate_display`, `test_atomic_aggregate_and_aggregator_roundtrip` |
| AGGREGATOR (type 7, optional transitive): ASN + IPv4 router-id | `pathvector-types/src/attr.rs` | ✅ | `test_aggregator_new`, `test_aggregator_display`, `test_aggregator_too_short_is_error` |
| Path attribute flag bits: Optional, Transitive, Partial, Extended Length | `pathvector-session/src/message/update.rs` | ✅ | `test_extended_length_encode_path`, `test_extended_length_origin_attribute` |
| Unknown transitive attributes preserved and Partial bit set on re-encode | `pathvector-session/src/message/update.rs` | ✅ | `test_unknown_optional_transitive_partial_bit_set_on_reencode`, `test_unknown_non_transitive_partial_bit_not_set`, `test_unknown_attribute_preserved` |

### §8 — Finite State Machine

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| States: Idle, Connect, Active, OpenSent, OpenConfirm, Established | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_manual_start_enters_connect`, `test_tcp_connected_from_active_enters_open_sent`, `test_receive_keepalive_enters_established` |
| ManualStart transitions Idle → Connect and initiates TCP | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_manual_start_enters_connect` |
| ManualStop from any state sends Cease NOTIFICATION and closes TCP | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_manual_stop_from_established_sends_cease`, `test_manual_stop_from_open_sent_sends_cease`, `test_manual_stop_from_open_confirm_sends_cease` |
| ManualStop from Idle is a no-op | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_manual_stop_from_idle_is_noop` |
| TcpConnected → OpenSent, sends OPEN | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_tcp_connected_sends_open`, `test_sent_open_has_correct_fields` |
| TcpFailed from Connect → Active | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_tcp_failed_from_connect_enters_active` |
| TcpFailed from Established → session terminated | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_tcp_failed_in_established_terminates_session` |
| Receive OPEN in OpenSent → send KEEPALIVE → OpenConfirm | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_receive_open_sends_keepalive_enters_open_confirm` |
| Receive KEEPALIVE in OpenConfirm → Established | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_receive_keepalive_enters_established` |
| Receive NOTIFICATION in OpenSent → Idle | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_notification_in_open_sent_goes_idle` |
| Receive NOTIFICATION in OpenConfirm → terminated | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_notification_in_open_confirm_terminates` |
| Receive NOTIFICATION in Established → session terminated | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_notification_in_established_emits_session_terminated` |
| Connect-retry timer (default 120 s) — fires → re-initiate TCP | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_connect_retry_timer_from_connect_reinitiates_tcp`, `test_connect_retry_from_active_enters_connect` |
| Hold timer negotiated as min(local, peer) | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_hold_time_negotiated_to_minimum` |
| Hold time 0 disables the hold and keepalive timers | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_hold_time_zero_disables_timers` |
| Keepalive interval is 1/3 of negotiated hold time | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_keepalive_interval_is_third_of_hold_time` |
| HoldTimerExpired in Established → NOTIFICATION + teardown | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_hold_timer_expired_in_established` |
| HoldTimerExpired in OpenSent → NOTIFICATION + teardown | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_hold_timer_expired_in_open_sent` |
| Receive UPDATE in Established resets hold timer | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_update_emits_route_update_and_resets_hold` |
| Receive KEEPALIVE in Established resets hold timer | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_keepalive_message_in_established_resets_hold_timer` |
| Unhandled inputs in non-Established states are no-ops | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_unhandled_input_in_connect_is_noop`, `test_unhandled_input_in_active_is_noop`, `test_unhandled_input_in_open_sent_is_noop`, `test_unhandled_input_in_open_confirm_is_noop` |
| Open hold timer (240 s) while awaiting peer OPEN in OpenSent | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_hold_timer_expired_in_open_sent` |
| Peer AS validation skipped when peer_as is unconfigured | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_open_accepted_when_peer_as_unconfigured` |
| Connection collision detection (higher BGP ID keeps outbound connection) | `pathvector-session/src/fsm/mod.rs` | ❌ | — |
| Full session lifecycle over real TCP sockets | `pathvector-session/tests/transport.rs` | ✅ | `interop: test_session_reaches_established` |
| Hold timer fires over real TCP → session terminated | `pathvector-session/tests/transport.rs` | ✅ | `interop: test_hold_timer_fires_terminates_session` |
| Peer disconnect detected and emits SessionTerminated | `pathvector-session/tests/transport.rs` | ✅ | `interop: test_peer_disconnect_emits_terminated` |
| Wrong peer AS over real TCP does not reach Established | `pathvector-session/tests/transport.rs` | ✅ | `interop: test_open_with_wrong_peer_as_does_not_establish` |
| UPDATE over real TCP emits RouteUpdate event | `pathvector-session/tests/transport.rs` | ✅ | `interop: test_update_message_emits_route_update_event` |

### §9.1 — Decision Process (Best-Path Selection)

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| Step 1: Prefer routes with reachable next-hop | `pathvector-rib/src/best_path.rs` | ❌ | — |
| Step 2: Prefer highest LOCAL_PREF (missing → 100) | `pathvector-rib/src/best_path.rs` | ✅ | `test_select_best_prefers_higher_local_pref`, `test_select_best_missing_local_pref_treated_as_100`, `test_select_best_local_pref_beats_path_length` |
| Step 3: Prefer locally originated routes | `pathvector-rib/src/best_path.rs` | ❌ | — |
| Step 4: Prefer shortest AS_PATH (AS_SET counts as 1; AS_CONFED_* count as 0) | `pathvector-rib/src/best_path.rs` | ✅ | `test_select_best_prefers_shorter_as_path`, `test_aspath_path_length_set_counts_as_one`, `test_aspath_path_length_confed_counts_as_zero` |
| Step 5: Prefer lowest ORIGIN (IGP < EGP < INCOMPLETE) | `pathvector-rib/src/best_path.rs` | ✅ | `test_select_best_prefers_lower_origin` |
| Step 6: Prefer lowest MED (missing → 0; same-AS comparison only) | `pathvector-rib/src/best_path.rs` | ✅ | `test_select_best_prefers_lower_med`, `test_select_best_missing_med_treated_as_zero` |
| Step 7: Prefer eBGP over iBGP | `pathvector-rib/src/best_path.rs` | ❌ | — |
| Step 8: Prefer lowest IGP metric to next-hop | `pathvector-rib/src/best_path.rs` | ❌ | — |
| Step 9: Prefer oldest eBGP route | `pathvector-rib/src/best_path.rs` | ❌ | — |
| Step 10: Prefer lowest peer IP address (tiebreaker) | `pathvector-rib/src/best_path.rs` | ✅ | `test_select_best_tiebreak_lower_peer_ip` |
| select_best returns None for an empty candidate set | `pathvector-rib/src/best_path.rs` | ✅ | `test_select_best_empty` |
| select_best returns the correct Route reference, not just PeerId | `pathvector-rib/src/best_path.rs` | ✅ | `test_select_best_returns_correct_route_reference` |

### §9.2 — RIB Structure

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| Adj-RIB-In: per-peer store of received routes before policy | `pathvector-rib/src/adj_rib_in.rs` | ✅ | `test_adj_rib_in_insert_and_get`, `test_adj_rib_in_withdraw`, `test_adj_rib_in_multiple_prefixes` |
| Adj-RIB-In: insert returns previous route for the same prefix | `pathvector-rib/src/adj_rib_in.rs` | ✅ | `test_adj_rib_in_insert_returns_old` |
| Adj-RIB-In: withdraw on absent prefix is a no-op | `pathvector-rib/src/adj_rib_in.rs` | ✅ | `test_adj_rib_in_withdraw_absent` |
| Loc-RIB: post-policy best routes selected for use | `pathvector-rib/src/loc_rib.rs` | ✅ | `test_loc_rib_insert_single`, `test_loc_rib_best_path_selects_higher_local_pref`, `test_loc_rib_best_updated_on_insert` |
| Loc-RIB: longest-prefix match for forwarding lookups | `pathvector-rib/src/loc_rib.rs` | ✅ | `test_loc_rib_longest_match` |
| Loc-RIB: withdraw last candidate removes the prefix entirely | `pathvector-rib/src/loc_rib.rs` | ✅ | `test_loc_rib_withdraw_last_candidate_removes_prefix` |
| Loc-RIB: withdraw one peer promotes the remaining candidate | `pathvector-rib/src/loc_rib.rs` | ✅ | `test_loc_rib_withdraw_peer_promotes_remaining_candidate` |
| Adj-RIB-Out: per-peer store of routes to be advertised | `pathvector-rib/src/adj_rib_out.rs` | ✅ | `test_adj_rib_out_insert_and_get`, `test_adj_rib_out_withdraw` |
| iBGP split horizon: routes from iBGP not re-advertised to iBGP peers | `pathvector-rib/src/adj_rib_out.rs` | ⚠️ | — (AdjRibOut exists; iBGP/eBGP distinction not enforced — see TODO) |

---

## RFC 2918 — Route Refresh Capability

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| RouteRefresh capability (code 2) advertised and decoded in OPEN | `pathvector-session/src/message/open.rs` | ✅ | `test_open_with_capabilities_roundtrip` |
| ROUTE-REFRESH message (type 5): AFI (2) + reserved (1) + SAFI (1) | `pathvector-session/src/message/route_refresh.rs` | ✅ | `test_ipv4_unicast_roundtrip`, `test_ipv6_unicast_roundtrip`, `test_evpn_roundtrip`, `test_known_wire_bytes` |
| ROUTE-REFRESH encoded length is 23 bytes | `pathvector-session/src/message/route_refresh.rs` | ✅ | `test_encoded_length` |
| ROUTE-REFRESH only sent/honoured when capability was negotiated | `pathvector-session/src/fsm/mod.rs` | ⚠️ | — (capability is parsed; send-guard not enforced — see TODO) |

---

## RFC 3392 — Capabilities Advertisement

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| Optional parameters encoded as type-length-value in OPEN | `pathvector-session/src/message/open.rs` | ✅ | `test_minimal_open_roundtrip`, `test_open_with_capabilities_roundtrip` |
| Optional parameter type 2 wraps capability TLVs | `pathvector-session/src/message/open.rs` | ✅ | `test_open_with_capabilities_roundtrip` |
| Unknown optional parameter types silently skipped | `pathvector-session/src/message/open.rs` | ✅ | `test_unknown_opt_param_type_is_skipped` |
| Unknown capability codes preserved without corruption | `pathvector-session/src/message/open.rs` | ✅ | `test_unknown_capability_preserved` |
| Truncated MultiProtocol capability (< 4 bytes) is an error | `pathvector-session/src/message/open.rs` | ✅ | `test_truncated_multiprotocol_capability_is_error` |
| Truncated FourByteAsn capability (< 4 bytes) is an error | `pathvector-session/src/message/open.rs` | ✅ | `test_truncated_four_byte_asn_capability_is_error` |
| Truncated GracefulRestart capability (< 2 bytes) is an error | `pathvector-session/src/message/open.rs` | ✅ | `test_truncated_graceful_restart_capability_is_error` |

---

## RFC 4760 — Multiprotocol Extensions for BGP-4

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| MultiProtocol capability (code 1): AFI (2) + reserved (1) + SAFI (1) | `pathvector-session/src/message/open.rs` | ✅ | `test_open_with_capabilities_roundtrip` |
| MP_REACH_NLRI (type 14): AFI, SAFI, next-hop, NLRI — IPv4 | `pathvector-session/src/message/update.rs` | ✅ | `test_mp_reach_ipv4_roundtrip` |
| MP_REACH_NLRI (type 14): AFI, SAFI, next-hop, NLRI — IPv6 | `pathvector-session/src/message/update.rs` | ✅ | `test_mp_reach_ipv6_roundtrip` |
| MP_REACH_NLRI: invalid next-hop length is an error | `pathvector-session/src/message/update.rs` | ✅ | `test_mp_reach_invalid_next_hop_length_is_error` |
| MP_REACH_NLRI: truncated body is an error | `pathvector-session/src/message/update.rs` | ✅ | `test_mp_reach_nlri_too_short_is_error` |
| MP_UNREACH_NLRI (type 15): AFI, SAFI, withdrawn NLRI — IPv4 | `pathvector-session/src/message/update.rs` | ✅ | `test_mp_unreach_ipv4_roundtrip` |
| MP_UNREACH_NLRI (type 15): AFI, SAFI, withdrawn NLRI — IPv6 | `pathvector-session/src/message/update.rs` | ✅ | `test_mp_unreach_ipv6_roundtrip` |
| MP_UNREACH_NLRI: truncated body is an error | `pathvector-session/src/message/update.rs` | ✅ | `test_mp_unreach_nlri_too_short_is_error` |
| MP_UNREACH_NLRI: unknown AFI produces empty prefix list (no panic) | `pathvector-session/src/message/update.rs` | ✅ | `test_mp_unreach_unknown_afi_produces_empty_prefixes` |
| IPv6 next-hop may carry both global unicast and link-local addresses | `pathvector-types/src/attr.rs` | ✅ | `test_next_hop_v6_with_link_local`, `test_mp_reach_ipv6_link_local_roundtrip` |
| AFI and SAFI type registry (IPv4, IPv6, L2VPN, and well-known SAFIs) | `pathvector-types/src/afi.rs` | ✅ | `test_afi_constants`, `test_safi_constants`, `test_afisafi_constants` |

---

## RFC 6793 — BGP Support for Four-Octet Autonomous System (AS) Numbers

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| Asn stored as 32-bit value | `pathvector-types/src/asn.rs` | ✅ | `test_asn_new_and_value`, `test_asn_is_four_byte` |
| AS_TRANS (23456) is a named constant | `pathvector-types/src/asn.rs` | ✅ | `test_asn_is_trans` |
| AS_TRANS substituted in 2-byte `my_as` field when local ASN > 65535 | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_four_byte_asn_preferred_over_my_as` |
| FourByteAsn capability (code 65): carries full 32-bit ASN | `pathvector-session/src/message/open.rs` | ✅ | `test_open_with_capabilities_roundtrip` |
| AS4_PATH (type 17): 4-byte AS path during 2-byte/4-byte transition | `pathvector-session/src/message/update.rs` | ✅ | `test_as4_path_roundtrip` |
| AS4_AGGREGATOR (type 18): 4-byte aggregator during transition | `pathvector-session/src/message/update.rs` | ✅ | `test_as4_aggregator_roundtrip`, `test_as4_aggregator_too_short_is_error` |
| When both peers support 4-byte ASN, FourByteAsn capability preferred over my_as field | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_four_byte_asn_preferred_over_my_as` |
| Full 4-byte ASN session confirmed against GoBGP | — | ✅ | `interop: GoBGP validation 2026-05-31` |

---

## RFC 4724 — Graceful Restart Mechanism for BGP

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| GracefulRestart capability (code 64): restart flags, restart time, per-family forwarding-preserved flag | `pathvector-session/src/message/open.rs` | ✅ | `test_graceful_restart_roundtrip` |
| Capability forwarded to caller via `SessionInfo` | `pathvector-session/src/fsm/mod.rs` | ✅ | `test_session_info_peer_capabilities_forwarded`, `test_session_info_graceful_restart_capability_forwarded` |
| FSM holds forwarding state while control plane restarts | `pathvector-session/src/fsm/mod.rs` | ❌ | — |
| Stale route timer — mark routes stale and withdraw after timer expires | `pathvector-rib` | ❌ | — |

---

## RFC 4486 — Subcodes for BGP Cease NOTIFICATION Message

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| All 10 Cease subcodes encode and decode correctly | `pathvector-session/src/message/notification.rs` | ✅ | `test_cease_all_variants_roundtrip` |
| Subcode 2 (Administrative Shutdown) carries optional diagnostic data | `pathvector-session/src/message/notification.rs` | ✅ | `test_cease_admin_shutdown_roundtrip` |
| ManualStop sends Cease over a real session | `pathvector-session/tests/transport.rs` | ✅ | `interop: test_manual_stop_sends_cease_and_emits_terminated` |

---

## RFC 1997 — BGP Communities Attribute

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| COMMUNITY (type 8): list of 32-bit values, written as high:low | `pathvector-types/src/community.rs` | ✅ | `test_community_new`, `test_community_from_parts_roundtrip`, `test_community_display` |
| Community encoded/decoded correctly in UPDATE | `pathvector-session/src/message/update.rs` | ✅ | `test_communities_roundtrip` |
| Community attribute with bad length is an error | `pathvector-session/src/message/update.rs` | ✅ | `test_community_bad_length_is_error` |
| Well-known community NO_EXPORT (0xFFFFFF01) | `pathvector-types/src/community.rs` | ✅ | `test_community_well_known_no_export` |
| Well-known community NO_ADVERTISE (0xFFFFFF02) | `pathvector-types/src/community.rs` | ✅ | `test_community_well_known_no_advertise` |
| Well-known community NO_EXPORT_SUBCONFED (0xFFFFFF03) | `pathvector-types/src/community.rs` | ✅ | `test_community_well_known_no_export_subconfed` |
| Operator-assigned community values do not collide with well-known range | `pathvector-types/src/community.rs` | ✅ | `test_community_operator_not_well_known` |
| Match on community value in policy | `pathvector-policy/src/condition.rs` | ✅ | `test_community_condition` |
| Add / remove community in policy action | `pathvector-policy/src/action.rs` | ✅ | `test_add_community`, `test_remove_community`, `test_set_communities` |

---

## RFC 4360 — BGP Extended Communities Attribute

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| EXTENDED_COMMUNITIES (type 16): list of 8-byte typed communities | `pathvector-types/src/community.rs` | ✅ | `test_extended_community_bytes_roundtrip`, `test_extended_community_display` |
| Type byte encodes IANA authority (high bit) and transitivity (bit 6) | `pathvector-types/src/community.rs` | ✅ | `test_extended_community_non_transitive` |
| Route Target subtype (type 0x00/0x01/0x02, subtype 0x02) byte layout | `pathvector-types/src/community.rs` | ✅ | `test_extended_community_route_target_as2`, `test_extended_community_route_target_as4` |
| Route Origin subtype byte layout | `pathvector-types/src/community.rs` | ✅ | `test_extended_community_route_origin_as2` |
| Extended communities encoded/decoded correctly in UPDATE | `pathvector-session/src/message/update.rs` | ✅ | `test_extended_communities_roundtrip` |
| Extended communities attribute with bad length is an error | `pathvector-session/src/message/update.rs` | ✅ | `test_extended_communities_bad_length_is_error` |

---

## RFC 8092 — BGP Large Communities Attribute

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| LARGE_COMMUNITY (type 32): list of 12-byte values (global-admin:local-data-1:local-data-2) | `pathvector-types/src/community.rs` | ✅ | `test_large_community_new`, `test_large_community_bytes_roundtrip`, `test_large_community_display` |
| Large communities encoded/decoded correctly in UPDATE | `pathvector-session/src/message/update.rs` | ✅ | `test_large_communities_roundtrip` |
| Large community attribute with bad length is an error | `pathvector-session/src/message/update.rs` | ✅ | `test_large_community_bad_length_is_error` |
| Match on large community value in policy | `pathvector-policy/src/condition.rs` | ✅ | `test_large_community_condition` |
| Add / remove large community in policy action | `pathvector-policy/src/action.rs` | ✅ | `test_add_large_community`, `test_remove_large_community` |

---

## RFC 7999 — BLACKHOLE Community

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| BLACKHOLE community value 0xFFFF029A defined as a named constant | `pathvector-types/src/community.rs` | ✅ | `test_community_blackhole` |
| `is_blackhole()` predicate returns true only for 0xFFFF029A | `pathvector-types/src/community.rs` | ✅ | `test_community_blackhole` |
| Routes carrying BLACKHOLE result in a discard/null-route action | `pathvector-policy` / `pathvectord` | ❌ | — |

---

## RFC 1930 — Guidelines for creation, selection, and registration of an AS

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| 2-byte private ASN range 64512–65534 recognised | `pathvector-types/src/asn.rs` | ✅ | `test_asn_is_private` |
| `is_private()` returns true for private ASNs and false for public ones | `pathvector-types/src/asn.rs` | ✅ | `test_asn_is_private` |

---

## RFC 6996 — Autonomous System (AS) Reservation for Private Use

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| 4-byte private ASN range 4200000000–4294967294 recognised | `pathvector-types/src/asn.rs` | ✅ | `test_asn_is_private` |

---

## RFC 5065 — Autonomous System Confederations for BGP

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| AS_CONFED_SEQUENCE (segment type 3) and AS_CONFED_SET (segment type 4) encode and decode | `pathvector-types/src/aspath.rs` | ✅ | `test_segment_display_confed_sequence`, `test_segment_display_confed_set`, `test_as_path_confed_segments_roundtrip` |
| Confederation segments count as 0 in AS path length (best-path step 4) | `pathvector-rib/src/best_path.rs` | ✅ | `test_aspath_path_length_confed_counts_as_zero` |
| Confederation segments stripped from AS_PATH before advertising to eBGP peers | `pathvector-rib/src/adj_rib_out.rs` | ❌ | — |

---

## RFC 4456 — BGP Route Reflection

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| ORIGINATOR_ID (type 9): router-id of originating route reflector client | `pathvector-types` / `pathvector-rib` | ❌ | — |
| CLUSTER_LIST (type 10): sequence of cluster IDs the route has passed through | `pathvector-types` / `pathvector-rib` | ❌ | — |
| Route reflector loop prevention using ORIGINATOR_ID and CLUSTER_LIST | `pathvector-rib` | ❌ | — |
| Route reflector client/non-client peer classification | `pathvector-session` / `pathvector-rib` | ❌ | — |

---

## RFC 3107 — Carrying Label Information in BGP-4

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| Safi::MPLS_LABELED (value 4) defined in AFI/SAFI registry | `pathvector-types/src/afi.rs` | ✅ | `test_safi_constants` |
| MPLS label stack encoding in NLRI | `pathvector-session/src/message/update.rs` | ❌ | — |

---

## RFC 4364 — BGP/MPLS IP Virtual Private Networks (VPNs)

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| Safi::MPLS_VPN (value 128) defined in AFI/SAFI registry | `pathvector-types/src/afi.rs` | ✅ | `test_safi_constants` |
| VPN-IPv4 address (8-byte RD + 4-byte prefix) NLRI encoding | `pathvector-session/src/message/update.rs` | ❌ | — |
| Route Distinguisher type parsing | `pathvector-types` | ❌ | — |

---

## RFC 4761 — Virtual Private LAN Service (VPLS) Using BGP

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| Safi::VPLS (value 65) and Afi::L2VPN (25) defined | `pathvector-types/src/afi.rs` | ✅ | `test_safi_constants`, `test_afi_constants` |
| VPLS NLRI encoding | `pathvector-session/src/message/update.rs` | ❌ | — |

---

## RFC 7432 — BGP MPLS-Based Ethernet VPN (EVPN)

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| Safi::EVPN (value 70) and Afi::L2VPN (25) defined | `pathvector-types/src/afi.rs` | ✅ | `test_safi_constants`, `test_afi_constants` |
| EVPN route type encoding (Type 1–5) | `pathvector-session/src/message/update.rs` | ❌ | — |

---

## RFC 5575 — Dissemination of Flow Specification Rules (FlowSpec)

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| Safi::FLOW_SPEC (value 133) defined in AFI/SAFI registry | `pathvector-types/src/afi.rs` | ✅ | `test_safi_constants` |
| FlowSpec NLRI component encoding (type, operator, value) | `pathvector-session/src/message/update.rs` | ❌ | — |

---

## RFC 8654 — Extended Message Support for BGP

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| Extended Message capability (code 6) decoded in OPEN | `pathvector-session/src/message/open.rs` | ❌ | — |
| When negotiated, allow UPDATE messages up to 65535 bytes | `pathvector-session/src/message/header.rs` | ❌ | — |

---

## RFC 7854 — BGP Monitoring Protocol (BMP)

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| BMP common header (version, length, type) | `pathvector-bmp/src/lib.rs` | ❌ | — |
| Per-peer header (peer type, flags, peer address, AS, BGP ID, timestamp) | `pathvector-bmp/src/lib.rs` | ❌ | — |
| Message type 0 — Route Monitoring: wraps BGP UPDATE | `pathvector-bmp/src/lib.rs` | ❌ | — |
| Message type 1 — Statistics Report | `pathvector-bmp/src/lib.rs` | ❌ | — |
| Message type 2 — Peer Down Notification | `pathvector-bmp/src/lib.rs` | ❌ | — |
| Message type 3 — Peer Up Notification | `pathvector-bmp/src/lib.rs` | ❌ | — |
| Message type 4 — Initiation Message | `pathvector-bmp/src/lib.rs` | ❌ | — |
| Message type 5 — Termination Message | `pathvector-bmp/src/lib.rs` | ❌ | — |
| Route Monitoring NLRI → `Route<A>` → `AdjRibIn` pipeline | `pathvector-bmp` / `pathvector-rib` | ❌ | — |

---

## RFC 2385 — Protection of BGP Sessions via the TCP MD5 Signature Option

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| TCP-MD5 socket option set on eBGP peering connections | `pathvector-session/src/transport/mod.rs` | ❌ | — |

---

## RFC 8205 — BGPsec Protocol Specification

| Requirement | Module | Status | Verified by |
|---|---|---|---|
| BGPsec_PATH attribute (type 36): cryptographic path validation | `pathvector-types` / `pathvector-session` | ❌ | — |

---

## Summary

| RFC | Subject | Overall Status |
|---|---|---|
| RFC 4271 | BGP-4 core protocol | ⚠️ Best-path steps 1/3/7/8/9 and collision detection outstanding |
| RFC 2918 | Route Refresh | ⚠️ Message and capability implemented; send-guard not enforced |
| RFC 3392 | Capability Advertisement | ✅ |
| RFC 4760 | Multiprotocol Extensions | ✅ |
| RFC 6793 | 4-Byte ASN | ✅ |
| RFC 4724 | Graceful Restart | ⚠️ Capability parsed; FSM restart behaviour not implemented |
| RFC 4486 | Cease NOTIFICATION Subcodes | ✅ |
| RFC 1997 | BGP Communities | ✅ |
| RFC 4360 | Extended Communities | ✅ |
| RFC 8092 | Large Communities | ✅ |
| RFC 7999 | BLACKHOLE Community | ⚠️ Value and predicate defined; discard action not wired |
| RFC 1930 | Private ASN (2-byte) | ✅ |
| RFC 6996 | Private ASN (4-byte) | ✅ |
| RFC 5065 | BGP Confederations | ⚠️ Segment types and path length correct; eBGP strip not implemented |
| RFC 4456 | Route Reflectors | ❌ |
| RFC 3107 | MPLS Labeled Unicast | ⚠️ SAFI defined; label encoding not implemented |
| RFC 4364 | MPLS L3VPN | ⚠️ SAFI defined; VPN-IPv4 NLRI not implemented |
| RFC 4761 | VPLS | ⚠️ SAFI/AFI defined; NLRI not implemented |
| RFC 7432 | EVPN | ⚠️ SAFI/AFI defined; route types not implemented |
| RFC 5575 | FlowSpec | ⚠️ SAFI defined; component encoding not implemented |
| RFC 8654 | Extended Message | ❌ |
| RFC 7854 | BGP Monitoring Protocol (BMP) | ❌ |
| RFC 2385 | TCP MD5 Authentication | ❌ |
| RFC 8205 | BGPsec | ❌ |

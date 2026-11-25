# RFC Requirements — pathvector-session

This crate owns the **wire protocol layer**: message codec, framing, BGP FSM, and
transport. It reads bytes off the wire and produces structured events; it writes
structured messages back to bytes. It has no routing logic and no RIB state.

**Status key:** ✅ Implemented and tested | ⚠️ Partial — see notes | ❌ Not started  
**Verified by key:** `test_name` — unit test | `proptest` — property test | `interop:x` — GoBGP/BIRD interop | `—` — no automated verification

---

## RFC 4271 §4 — Message Formats

**Owns:** Encode and decode for all four BGP message types: OPEN, UPDATE, NOTIFICATION, KEEPALIVE, plus the common 19-byte header (16-byte marker, 2-byte length, 1-byte type).  
**Boundary:** Path attribute semantics (what the values mean) live in `pathvector-types`.
Decision-making on received routes lives in `pathvector-rib`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4271#section-4

| Requirement | File | Status | Verified by |
|---|---|---|---|
| 19-byte header: 16-byte all-ones marker, 2-byte length, 1-byte type | `src/message/` | ✅ | `test_header_roundtrip`, `test_header_bad_marker` |
| OPEN message encode/decode: version, my-as, hold-time, bgp-id, optional-params | `src/message/` | ✅ | `test_open_roundtrip`, `test_open_invalid_version`, interop:gobgp |
| §6.2: an OPEN optional parameter whose Parameter Type isn't recognized (only type 2, Capabilities, is understood) → NOTIFICATION(OPEN Error, Unsupported Optional Parameter) | `src/message/open.rs`, `src/transport/mod.rs` | ✅ | Fixed 2026-07-31 (`fix/rfc4271-unrecognized-optional-parameter-and-attribute`). `decode_capabilities` returns `CodecError::UnsupportedOptionalParameter`; `header_error_notification` maps it to the NOTIFICATION. Confirmed via direct RFC 5492 read that it doesn't revise this clause — RFC 5492's own Unsupported Capability subcode (7) is for a *recognized* Capabilities parameter carrying an unsupported capability, a distinct case. `test_unknown_opt_param_type_is_rejected`, `test_authentication_opt_param_type_1_is_rejected`, `test_unrecognized_opt_param_after_valid_capabilities_still_rejected`, `test_unsupported_optional_parameter_sends_open_message_notification` |
| UPDATE message encode/decode: withdrawn-routes, path-attributes, NLRI | `src/message/` | ✅ | `test_update_roundtrip`, `test_update_empty`, interop:gobgp |
| NOTIFICATION message encode/decode: error-code, error-subcode, data | `src/message/` | ✅ | `test_notification_roundtrip`, `test_notification_cease` |
| KEEPALIVE message encode/decode (header only, no body) | `src/message/` | ✅ | `test_keepalive_roundtrip` |
| Attribute flags: Optional, Transitive, Partial, Extended-Length — wire encode/decode round-trip | `src/message/` | ✅ | `test_attribute_flags_roundtrip`, `test_extended_length_attribute` |
| Attribute flags: reject a *received* attribute whose flags don't match what its type requires (well-known ⇒ Transitive=1; well-known/optional-non-transitive ⇒ Partial=0) — "Attribute Flags Error", UPDATE Message Error subcode 4 | `src/message/update.rs` | ✅ | Fixed 2026-07-17 (`fix/rfc7606-attribute-flags-cluster`), per RFC 7606 §3(c)'s revised remediation (treat-as-withdraw, not session reset; Optional/Transitive only, not Partial — see `RFC_AUDIT.md` §4.3/§3(c)). `expected_optional_transitive` gives the required flags per known type, checked in `decode_path_attributes` before value decode. `test_well_known_attribute_marked_optional_is_treat_as_withdraw`, `test_well_known_attribute_missing_transitive_bit_is_treat_as_withdraw`, `test_optional_transitive_attribute_marked_non_transitive_is_treat_as_withdraw`, `test_correct_flags_do_not_trigger_flags_conflict`, `test_unrecognized_optional_attribute_any_flags_no_conflict` |
| ORIGIN (type 1) encode/decode | `src/message/` | ✅ | `test_attr_origin_roundtrip` |
| AS_PATH (type 2) encode/decode with AS_SEQUENCE and AS_SET segments | `src/message/` | ✅ | `test_attr_aspath_roundtrip`, `test_attr_aspath_with_set` |
| NEXT_HOP (type 3) encode/decode | `src/message/` | ✅ | `test_attr_next_hop_roundtrip` |
| MULTI_EXIT_DISC (type 4) encode/decode | `src/message/` | ✅ | `test_attr_med_roundtrip` |
| LOCAL_PREF (type 5) encode/decode | `src/message/` | ✅ | `test_attr_local_pref_roundtrip` |
| ATOMIC_AGGREGATE (type 6) encode/decode | `src/message/` | ✅ | `test_attr_atomic_aggregate_roundtrip` |
| AGGREGATOR (type 7) encode/decode | `src/message/` | ✅ | `test_attr_aggregator_roundtrip` |
| COMMUNITY (type 8) encode/decode — RFC 1997 | `src/message/` | ✅ | `test_attr_community_roundtrip` |
| EXTENDED_COMMUNITIES (type 16) encode/decode — RFC 4360 | `src/message/` | ✅ | `test_attr_extended_community_roundtrip` |
| LARGE_COMMUNITY (type 32) encode/decode — RFC 8092 | `src/message/` | ✅ | `test_attr_large_community_roundtrip` |
| Unknown optional transitive attributes preserved in Partial flag | `src/message/` | ✅ | `test_unknown_optional_transitive_preserved` — codec round-trip only (decode a message, re-encode the *same* message object); the separate RIB-pipeline question of whether an unknown attribute survives being *relayed* through this router to a different peer is `pathvector-rib`/`pathvectord`'s concern, tracked in their own `RFC.md`s (fixed 2026-08-03, see `RFC_AUDIT.md` §5) |

**§4.1 padding rejection — fixed 2026-08-03** (`fix/rfc4271-message-padding-rejection`).
"Length field MUST have the smallest value required... padding of extra
data after the message is not allowed" was already enforced for KEEPALIVE
(`decode_with_limit_and_caps` checks `cur.remaining() != 0`) but not for
OPEN or ROUTE_REFRESH — their decoders stopped after reading known/
declared-length fields without confirming the cursor was empty, silently
discarding any trailing padding within the declared header Length. Both
arms now carry the identical check. UPDATE and NOTIFICATION remain
unaffected by design (their trailing fields are defined as "consume the
rest of the message" by the RFC itself). Checked RFC 7606 and RFC 8654
directly for an amendment to this clause — neither mentions padding.
`test_open_with_trailing_padding_is_error`,
`test_open_with_trailing_padding_after_capabilities_is_error`,
`test_route_refresh_with_trailing_padding_is_error`. See `RFC_AUDIT.md`
§4.1 for detail.

---

## RFC 4271 §6.1 — Message Header Error Handling

**Owns:** Sending the RFC-mandated NOTIFICATION before closing the connection when the
19-byte header itself is malformed (bad marker, bad length, unrecognized type) — distinct
from RFC 7606, which only governs attribute-level errors within an otherwise well-framed
UPDATE.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4271#section-6.1

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Bad marker (not all-ones) → NOTIFICATION(Message Header Error, Connection Not Synchronized) before close | `src/transport/mod.rs` | ✅ | `test_invalid_marker_sends_message_header_notification`; e2e:fault_injection `bad_marker_daemon_stays_healthy` |
| Bad length (outside 19..=4096, or inconsistent) → NOTIFICATION(Message Header Error, Bad Message Length), Data = erroneous length | `src/transport/mod.rs` | ✅ | `test_invalid_length_sends_message_header_notification_with_length_in_data`; e2e:fault_injection `bad_length_daemon_stays_healthy` |
| Unrecognized message type → NOTIFICATION(Message Header Error, Bad Message Type), Data = erroneous type | `src/transport/mod.rs` | ✅ | `test_unknown_message_type_sends_message_header_notification_with_type_in_data`; e2e:fault_injection `bad_type_daemon_stays_healthy` |
| A fault on one peer's connection must not affect any other peer's session (one `tokio::spawn`ed task per peer) | `src/transport/mod.rs` | ✅ | e2e:fault_injection — every scenario asserts the control peer stays Established throughout |

**Deferred:** most `CodecError` variants below the header layer (malformed OPEN/NOTIFICATION
bodies — not RFC 7606-eligible, since that policy is UPDATE-only) are not yet mapped to a
NOTIFICATION; the connection is dropped silently, matching prior behavior. See TODO.md.
One exception is now handled: `CodecError::UnsupportedOptionalParameter` (RFC 4271 §6.2,
see the §4 table above) — the rest remain deferred.

---

## RFC 4271 §8 — BGP Finite State Machine

**Owns:** The full 6-state FSM (Idle → Connect → Active → OpenSent → OpenConfirm → Established), timer logic (ConnectRetry, Hold, Keepalive), and event dispatch.  
**Boundary:** Connection collision coordination (choosing which session to drop when two
peers simultaneously open) involves `pathvectord` as the authority on which session to
keep.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4271#section-8

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Idle → Connect on Start event | `src/fsm/mod.rs` | ✅ | `test_manual_start_enters_connect` |
| Connect → OpenSent on TCP connection established | `src/fsm/mod.rs` | ✅ | `test_tcp_connected_sends_open`, interop:gobgp, interop:bird |
| OpenSent → OpenConfirm on valid OPEN received | `src/fsm/mod.rs` | ✅ | `test_receive_open_sends_keepalive_enters_open_confirm`, interop:gobgp, interop:bird |
| OpenConfirm → Established on KEEPALIVE received | `src/fsm/mod.rs` | ✅ | `test_receive_keepalive_enters_established`, interop:gobgp, interop:bird |
| Any state → Idle on Hold Timer expiry | `src/fsm/mod.rs` | ✅ | `test_hold_timer_expired_in_established`, `test_hold_timer_expired_in_open_sent` |
| Hold Timer expiry (OpenSent/OpenConfirm/Established) schedules automatic reconnect via ConnectRetryTimer | `src/fsm/mod.rs` | ✅ | `test_hold_timer_expired_in_open_sent`, `test_hold_timer_expired_in_open_confirm`, `test_hold_timer_expired_in_established`; e2e:fault_injection `mid_session_tcp_reset_recovers_cleanly` |
| §8.2.2 `ManualStop`, and a stop carrying a NOTIFICATION (`NotificationToSend`), end in Idle from every state with no reconnect, cancelling one already pending | `src/fsm/mod.rs`, `src/transport/mod.rs` | ✅ | `stopped_session_stays_down`, `administrative_notification_stays_down`, `stop_while_a_retry_is_pending_cancels_it`, `test_notification_to_send_stops_every_state`, `notification_before_established_stops_the_session` |
| §8.1.2 Event 8 `AutomaticStop`: send the NOTIFICATION, go to Idle, restart after the ConnectRetry interval (restart timing is local policy, §8.1.1). Applied in Established only; ignored in other states, though §8.2.2 also acts on it in Connect through OpenConfirm | `src/fsm/mod.rs`, `src/transport/mod.rs` | ⚠️ | `test_established_automatic_stop_schedules_reconnect`, `test_idle_ignores_automatic_stop`, `automatic_stop_reconnects` |
| §8.2.2 Idle refuses incoming connections | `src/transport/mod.rs` | ✅ | `inbound_connection_in_idle_is_closed` |
| Keepalive timer fires at ⌊hold-time / 3⌋ seconds | `src/fsm/mod.rs` | ✅ | `test_keepalive_interval_is_third_of_hold_time` |
| NOTIFICATION sent before session close | `src/fsm/mod.rs` | ✅ | `test_bad_peer_as_sends_notification`, `test_unacceptable_hold_time_sends_notification` |
| §8.2.2 Events 9–11: expired timers are serviced however much input is ready, whether or not the peer reads and whether or not events are consumed (issue #102) | `src/transport/mod.rs`, `src/transport/schedule.rs` | ✅ | `overdue_keepalive_is_sent_while_updates_stay_ready`, `hold_timer_expires_under_a_flood_of_non_restarting_messages`, `overdue_connect_retry_is_serviced_while_commands_stay_ready`, `hold_timer_runs_while_a_write_is_blocked`, `keepalives_continue_while_the_event_channel_is_full`, `silent_peer_is_timed_out_while_the_event_channel_is_full`; `every_overdue_timer_is_serviced_within_a_bounded_number_of_turns`, `any_interleaving_stays_up_and_converges` (properties) |
| §8.2.2 Established: sending a KEEPALIVE or UPDATE restarts the KeepaliveTimer | `src/transport/mod.rs` | ✅ | `sending_an_update_restarts_the_keepalive_timer` |
| §4.4: KEEPALIVEs often enough not to expire the peer's HoldTimer, under load | `src/transport/mod.rs` | ✅ | `flooded_and_control_sessions_both_keep_cadence`, `any_interleaving_stays_up_and_converges` |
| §8.2.2: a stop takes effect while writes are blocked or events are not being consumed | `src/transport/mod.rs` | ✅ | `terminated_is_emitted_when_the_notification_cannot_be_written`, `stop_takes_effect_while_a_write_is_blocked`, `stop_takes_effect_while_the_event_channel_is_full` |
| §10: jitter SHOULD be applied to the KeepaliveTimer and ConnectRetryTimer | — | ❌ | — see `TODO.md` |
| §8.2.2 a teardown completes (routes deleted, state Idle, any restart scheduled) when the NOTIFICATION cannot be written | `src/transport/mod.rs` | ✅ | `failed_notification_write_on_automatic_stop_still_terminates_and_reconnects`, `failed_notification_write_on_hold_expiry_still_terminates_and_reconnects`, `failed_notification_write_on_stop_still_terminates_and_stays_down`, `failed_notification_write_in_open_sent_still_reconnects` |
| Hold time of 0 disables hold timer and keepalive | `src/fsm/mod.rs` | ✅ | `test_hold_time_zero_disables_timers` |
| §8.1 ConnectRetry timer is configurable (`SessionConfig.connect_retry_time`); FSM respects value from transport layer | `src/transport/mod.rs` | ✅ | `DEFAULT_CONNECT_RETRY_TIME` constant; exercised by `gr_phase2_eor_prunes_stale_routes_not_refreshed_by_peer` (2 s config) |
| §8.2.2 Events 27/28 (`UpdateMsg`/`UpdateMsgErr`) are handled by *state* before any RFC 7606 recovery: Idle ignores; Connect/Active stop the ConnectRetryTimer, drop TCP, → Idle; OpenSent/OpenConfirm send Finite State Machine Error (RFC 6608 subcode 1/2, Data = the 1-octet type of the unexpected message, 2 for UPDATE per §4), drop TCP, → Idle — for a normal UPDATE *and* every malformed-UPDATE outcome (session reset, treat-as-withdraw, attribute discard); no route event leaves the session before Established | `src/fsm/mod.rs`, `src/fsm/recovery.rs`, `src/transport/mod.rs` | ✅ | Fixed (issue #98). `rfc4271_8_2_2_idle_ignores_update_and_every_malformed_recovery_outcome`, `rfc4271_8_2_2_connect_and_active_drop_to_idle_on_update_and_every_malformed_outcome`, `rfc4271_8_2_2_open_sent_sends_fsm_error_for_update_and_every_malformed_outcome`, `rfc4271_8_2_2_open_confirm_sends_fsm_error_for_update_and_every_malformed_outcome`, `rfc4271_8_2_2_route_update_is_never_emitted_outside_established`, `rfc6608_4_fsm_error_data_is_the_unexpected_message_type`, `rfc4271_8_2_2_malformed_update_matches_normal_update_before_established` (FSM matrix, `src/fsm/update_error_tests.rs`); real-TCP/real-codec `open_sent_update_of_every_recovery_outcome_is_an_fsm_error_with_no_route_event`, `open_confirm_update_of_every_recovery_outcome_is_an_fsm_error_with_no_route_event` (`tests/malformed_update_fsm.rs`) |
| §8.2.2 Established Event 27: a recovered (treat-as-withdraw / attribute-discard) UPDATE is processed like any UPDATE and **restarts the HoldTimer** (previously it did not) | `src/fsm/mod.rs` | ✅ | Fixed (issue #98). `rfc7606_2_attribute_discard_is_processed_as_event_27_with_hold_timer_restart`, `rfc7606_2_treat_as_withdraw_emits_withdrawal_and_restarts_hold_timer`; real-TCP `established_recovered_updates_restart_the_hold_timer` |
| §8.2.2 Established Event 28: a session-reset recovery sends the exact Update-error NOTIFICATION (+ Data), drops TCP, deletes routes (`Terminated(OperatorStop)`) and schedules a reconnect | `src/fsm/mod.rs` | ✅ | `rfc4271_8_2_2_established_session_reset_sends_exact_update_error_and_reconnects`, `rfc7606_5_2_missing_nlri_escalates_to_malformed_attribute_list_reset`, `rfc7606_3_h_session_reset_beats_weaker_errors_in_the_same_update`; real-TCP `established_session_reset_sends_exact_notification_then_reconnects` |

---

## RFC 9687 — Send Hold Timer (updates RFC 4271)

**Owns:** The `SendHoldTime` session attribute, `SendHoldTimer`, Event 29 and NOTIFICATION error code 8.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc9687

| Requirement | File | Status | Verified by |
|---|---|---|---|
| §4.1 per-connection `SendHoldTime` | `src/fsm/send_hold.rs`, `SessionConfig::send_hold_time` | ✅ | `configured_send_hold_time_applies` |
| §4.2 Event 29 `SendHoldTimer_Expires` | `src/fsm/mod.rs` (`FsmInput::SendHoldTimerExpired`) | ✅ | `send_hold_expiry_in_established_notifies_closes_and_goes_idle`, `send_hold_expiry_outside_established_is_ignored` |
| §4.3 OpenConfirm/Event 26 starts the timer if `SendHoldTime` is non-zero | `src/fsm/mod.rs` | ✅ | `send_hold_timer_starts_on_entering_established_and_not_before` |
| §4.3 Established/Event 29: log, release resources, drop TCP without waiting for the NOTIFICATION, → Idle | `src/fsm/mod.rs`, `src/transport/mod.rs` | ✅ | `peer_that_stops_reading_is_closed_after_the_default_send_hold_time`, `peer_with_a_closed_window_is_disconnected` (real TCP zero window) |
| §4.3 each message sent restarts the timer | `src/transport/mod.rs` | ✅ | `each_completed_send_restarts_the_send_hold_timer`, `healthy_idle_session_never_expires` |
| §4.3 stopped when `SendHoldTime` or the negotiated `HoldTime` is zero | `src/fsm/send_hold.rs` | ✅ | `send_hold_timer_does_not_run_when_disabled_or_without_a_hold_time`, `zero_hold_time_session_has_no_send_hold_timer`. The OpenConfirm text starts the timer whenever `SendHoldTime` is non-zero; with a zero `HoldTime` there are no KEEPALIVEs to restart it, so it is not started at all |
| §4.3 stopped on any transition out of Established | `src/fsm/mod.rs` | ✅ | `every_exit_from_established_stops_the_send_hold_timer_first` |
| §4.4 non-zero `SendHoldTime` MUST exceed `HoldTime` | `src/fsm/send_hold.rs` | ✅ | `configured_value_must_exceed_hold_time`, `a_running_timer_always_exceeds_hold_time` (property) |
| §5 connection MUST be closed and an error MUST be logged | `src/transport/mod.rs` | ✅ | `send_hold_expiry_logs_an_error_naming_the_error_code` |
| §6 enabled by default; default is the greater of 8 minutes and 2 × negotiated `HoldTime` | `src/fsm/send_hold.rs` | ✅ | `recommended_value_is_the_greater_of_8_minutes_and_twice_hold_time`, `default_send_hold_time_follows_the_negotiated_hold_time` |
| §6/§9 error code 8, subcode 0, no data | `src/message/notification.rs` | ✅ | `test_send_hold_timer_expired_is_code_8_subcode_0_without_data` |
| §7 SHOULD expose the reason as operational state | `pathvectord/src/metrics.rs` | ✅ | `terminated_reason_is_labeled_correctly` (`reason="send_hold_timer_expired"`) |
| §4.3 increment `ConnectRetryCounter`, peer oscillation damping | — | ❌ | Neither exists for any event (damping is optional) |

No interoperability test against another implementation has been run for this RFC.

---

## RFC 7606 — Revised Error Handling for BGP UPDATE Messages

**Owns:** Per-attribute error handling policy: when to treat-as-withdraw, when to discard
the attribute, when to reset the session.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc7606

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Malformed ORIGIN: treat-as-withdraw | `src/message/` | ✅ | `test_rfc7606_malformed_origin_treat_as_withdraw` |
| Malformed AS_PATH: treat-as-withdraw | `src/message/` | ✅ | `test_rfc7606_malformed_aspath_treat_as_withdraw` |
| Malformed NEXT_HOP: treat-as-withdraw | `src/message/` | ✅ | `test_rfc7606_malformed_next_hop_treat_as_withdraw` |
| Malformed LOCAL_PREF: treat-as-withdraw | `src/message/` | ✅ | `test_rfc7606_malformed_local_pref_treat_as_withdraw` |
| Unknown optional non-transitive attribute: attribute-discard | `src/message/` | ✅ | `test_rfc7606_unknown_optional_nontransitive_discarded` |
| Missing well-known mandatory attribute: **treat-as-withdraw** | `pathvectord/src/daemon/route.rs` | ✅ | **Fixed 2026-07-16** (GH [#31](https://github.com/dbrucknr/pathvector/pull/31), `fix/rfc7606-missing-mandatory-attribute`), originally found 2026-07-16 by `RFC_AUDIT.md`. `handle_update` (`pathvectord/src/daemon/route.rs:1029-1105`) now withdraws the affected route (Adj-RIB-In and LocRib, both v4 and v6) when ORIGIN/AS_PATH/(traditional-v4) NEXT_HOP is missing, per RFC 7606 §3(d): "If any of the well-known mandatory attributes are not present in an UPDATE message, then 'treat-as-withdraw' MUST be used." A NOTIFICATION/session-reset is sent only for the narrower RFC 7606 §5.2 exception — an UPDATE with no reachable NLRI at all (traditional or MP_REACH, including unsupported AFI/SAFI) plus a missing mandatory attribute, where the message can't be confidently treat-as-withdrawn — closed via a 4-round follow-up (GH [#41](https://github.com/dbrucknr/pathvector/pull/41), `fix/rfc7606-missing-nlri-session-reset`) after an independent Codex review of #31 found the §5.2 carve-out had been missed at both the daemon and transport layers. Verified by `missing_origin_treated_as_withdraw_no_notification`, `missing_as_path_treated_as_withdraw_no_notification`, `missing_next_hop_for_traditional_ipv4_treated_as_withdraw_no_notification`, `missing_origin_withdraws_preexisting_route_for_same_prefix`, `missing_origin_withdraws_preexisting_v6_route_for_same_prefix`, `withdraw_only_update_no_notification_for_missing_attrs`, `all_mandatory_attributes_present_no_notification`, `missing_origin_with_unsupported_afi_safi_mp_reach_no_notification`, `regression_missing_mandatory_attr_in_drain_loop_treated_as_withdraw`, `malformed_update_missing_origin_no_notification_route_not_installed` (`pathvectord/src/daemon/mod.rs`) for the treat-as-withdraw path, and `missing_nlri_update_with_attributes_resets_session`, `legacy_empty_update_no_notification` (plus `mp_unreach_only_eor_no_notification`) for the §5.2 session-reset exception and its legitimate NLRI-less no-op cases. See `RFC_AUDIT.md`'s RFC 7606 section and `TODO.md` #19 for the full history. |
| §7.7: AGGREGATOR malformed if length ≠ 6 (4-octet AS number capability not negotiated bilaterally with the peer) or ≠ 8 (negotiated) → attribute discard | `src/message/update.rs`, `src/framing/mod.rs`, `src/transport/mod.rs` | ✅ | Fixed 2026-07-31 (`fix/rfc7606-aggregator-capability-length`). `decode_attr_value`'s `four_byte_asn: bool` parameter (threaded from `decode_path_attributes` → `UpdateMessage::decode` → `BgpMessage::decode_with_limit_and_caps`) picks 6 vs. 8 bytes; `BgpCodec` tracks `four_byte_asn_negotiated` (mirroring the existing `set_extended_message`/RFC 8654 pattern) and the transport layer's `SessionEstablished` handler computes it as `peer_capabilities.contains(FourByteAsn) && local config.capabilities.contains(FourByteAsn)` — the same bilateral-negotiation shape as the existing `ExtendedMessage` check. `test_aggregator_6_bytes_valid_in_two_byte_asn_mode`, `test_aggregator_8_bytes_malformed_in_two_byte_asn_mode`, `test_aggregator_6_bytes_malformed_in_four_byte_asn_mode` (decoder-level, isolated). Also `test_aggregator_decoding_when_four_byte_asn_negotiated_bilaterally`/`test_aggregator_decoding_when_four_byte_asn_not_negotiated` (`tests/transport.rs`) — real-TCP integration tests proving the full chain (peer/local OPEN capabilities → FSM negotiation → `SessionEstablished` → `BgpTransport::set_four_byte_asn` → `BgpCodec`'s actual decode behavior), added per a Codex PR review suggesting the decoder-level tests alone didn't prove the production wiring end to end. |
| **Not amended by RFC 7606** — RFC 4271 §6.3: an unrecognized well-known attribute (unrecognized type code, Optional bit = 0) → NOTIFICATION(UPDATE Error, Unrecognized Well-known Attribute), Data = (type, length, value) — a full session reset, unlike the treat-as-withdraw/discard policies RFC 7606 assigns to the attribute-value errors above | `src/message/update.rs`, `src/transport/mod.rs` | ✅ | Fixed 2026-07-31 (`fix/rfc4271-unrecognized-optional-parameter-and-attribute`). Confirmed via direct RFC 7606 read that its §3 revisions are an explicit, exhaustive (a)-(j) list that never mentions this subcode. `decode_path_attributes` checks the Optional bit for any unrecognized type code (an Optional bit set — a legitimate unrecognized *optional* attribute — is unaffected, still `PathAttribute::Unknown`); `AttributeErrorPolicy::SessionReset` carries the specific `NotificationError`/Data so `handle_malformed_update` doesn't hardcode Malformed Attribute List for every session-reset case. **2026-08-03→08-04 detour:** briefly revised to treat-as-withdraw after checking BIRD's `bgp_decode_attrs` (`proto/bgp/attrs.c`), which uses its `WITHDRAW` path (session stays up) here rather than `REJECT`. Reverted the next day after code review flagged it as a compliance regression — §6.3 is an unamended MUST with no ambiguity for BIRD's differing practice to resolve, unlike areas where the RFC is genuinely silent (e.g. RFC 4724 §4.1's deferral scope, where this project does follow BIRD). `test_unrecognized_well_known_attribute_is_session_reset`, `test_unrecognized_well_known_attribute_extended_length_data_field`, `test_unrecognized_well_known_attribute_sends_correct_notification_and_terminates`. **e2e coverage added 2026-08-05** (review of PR #48, which is docs-only and correctly claimed "real NOTIFICATION bytes on the wire" for other tests but not for `test_unrecognized_well_known_attribute_sends_correct_notification_and_terminates`, which actually uses `MockTransport` with a pre-decoded `MalformedUpdate`): `tests/transport.rs`'s `test_raw_unrecognized_well_known_attribute_sends_real_notification_bytes` sends a hand-rolled raw UPDATE frame over a real loopback TCP socket and decodes the resulting NOTIFICATION with the real `BgpCodec` on the peer's side — the full raw-bytes-in, raw-bytes-out round trip. **Docker/testcontainers e2e coverage added 2026-08-05, round 2** (Codex follow-up review — the lowest-priority of the round-2 follow-ups, since the raw-loopback-TCP test above already proved the real wire codec on both ends; this adds a separate-container peer plus an unaffected control peer, which the loopback test structurally cannot): `pathvector-e2e/src/bin/mock_bgp_fault_peer.rs` gained an `unrecognized-well-known-attribute` scenario (real OPEN/KEEPALIVE handshake, then an UPDATE carrying the mandatory well-known attributes plus one `PathAttribute::Unknown` with the Optional bit clear) and `pathvector-e2e/tests/fault_injection.rs`'s `unrecognized_well_known_attribute_resets_session` asserts, via the fault peer's `SCENARIO_OUTCOME:` log line, both the exact `NotificationError` variant and the exact Data field bytes (type, length, value) — plus that `FaultInjectionHarness`'s paired GoBGP control peer stays Established throughout, satisfying Codex's "exact NOTIFICATION plus unaffected control peer" request. Real-teeth verified: temporarily disabled the `flags & FLAG_OPTIONAL == 0` check in `update.rs`, confirmed the test failed (NOTIFICATION never arrived, `wait_for_docker_log` timed out), reverted (clean no-op diff) and reconfirmed passing. |

---

## RFC 2918 — Route Refresh Capability for BGP-4

**Owns:** ROUTE-REFRESH message codec and capability advertisement.  
**Boundary:** RFC 7313 (Enhanced Route Refresh) repurposes the reserved byte as a subtype — owned here.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc2918

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Capability code 2 advertised in OPEN | `src/message/` | ✅ | `test_capability_route_refresh_in_open` |
| ROUTE-REFRESH message (type 5) encode/decode with AFI + reserved + SAFI | `src/message/route_refresh.rs` | ✅ | `test_route_refresh_roundtrip` |
| Outbound ROUTE-REFRESH send via `SessionCommand::RouteRefresh` | `src/transport/mod.rs` | ✅ | — |
| `Capability::RouteRefresh` advertised in local OPEN | `pathvectord/src/daemon.rs` | ✅ | — |
| `route_refresh_peers` populated only when both sides negotiated | `pathvectord/src/daemon.rs` | ✅ | `on_established_tracks_route_refresh_when_both_sides_negotiated`, `on_established_does_not_track_route_refresh_when_peer_omits_capability` |
| `SoftReset` returns `FAILED_PRECONDITION` if capability not negotiated (RFC 2918 §4) | `pathvectord/src/grpc.rs` | ✅ | `soft_reset_returns_failed_precondition_when_route_refresh_not_negotiated` |

---

## RFC 7313 — Enhanced Route Refresh Capability for BGP-4

**Owns:** `RouteRefreshSubtype` codec — repurposing the reserved byte as `Refresh` (0),
`BeginRefresh` (1), `EndRefresh` (2) subtypes.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc7313

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Subtype 0 (Refresh) — normal ROUTE-REFRESH | `src/message/route_refresh.rs` | ✅ | `test_route_refresh_subtype_refresh_default`, `prop_route_refresh_roundtrip` |
| Subtype 1 (BeginRefresh) encode/decode | `src/message/route_refresh.rs` | ✅ | `test_route_refresh_subtype_begin_refresh` |
| Subtype 2 (EndRefresh) encode/decode | `src/message/route_refresh.rs` | ✅ | `test_route_refresh_subtype_end_refresh` |
| Unknown subtype preserved (not mapped to error) | `src/message/route_refresh.rs` | ✅ | `test_route_refresh_subtype_unknown` |

---

## RFC 9003 — Extended BGP Administrative Shutdown Communication

**Owns:** Encoding and decoding the UTF-8 shutdown reason string in the CEASE
NOTIFICATION `data` field.  
**Boundary:** The `AdministrativeShutdown` subcode and NOTIFICATION framing live in
RFC 4486 / RFC 4271; this RFC only governs the `data` payload format.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc9003

| Requirement | File | Status | Verified by |
|---|---|---|---|
| `data` field: 1-byte length prefix + UTF-8 string, max 128 bytes | `src/message/notification.rs` | ✅ | `test_rfc9003_encode_decode_roundtrip` |
| Strings longer than 128 bytes truncated on encode | `src/message/notification.rs` | ✅ | `test_rfc9003_message_truncated_to_128_bytes` |
| Empty `data` returns `None` (not an error) | `src/message/notification.rs` | ✅ | `test_rfc9003_empty_data_returns_none` |
| Length byte exceeding remaining data handled safely | `src/message/notification.rs` | ✅ | `test_rfc9003_length_byte_exceeds_remaining_data` |
| `AdministrativeShutdown` NOTIFICATION with reason round-trips | `src/message/notification.rs` | ✅ | `test_rfc9003_shutdown_notification_roundtrips` |
| `AdministrativeReset` NOTIFICATION with reason round-trips | `src/message/notification.rs` | ✅ | `test_rfc9003_admin_reset_roundtrips` |

---

## RFC 5492 — Capabilities Advertisement with BGP-4

**Owns:** Optional parameter TLV encoding (type 2 = Capability) in OPEN; parsing capability
list; NOTIFICATION for unsupported capabilities.  
**Boundary:** Individual capability semantics owned by the RFC that defines them.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc5492

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Optional parameter type 2 TLV parsed as capability list | `src/message/` | ✅ | `test_capability_tlv_roundtrip` |
| Multiple Capabilities Optional Parameters in one OPEN (not just one) MUST be accepted and processed identically to a single parameter | `src/message/open.rs` `decode_capabilities` | ✅ | Added 2026-07-16 by `RFC_AUDIT.md` — the outer loop over optional parameters appends every type-2 parameter's capability TLVs into the same flat `Vec`, regardless of how many separate type-2 parameters there are |
| Peer capability we don't recognize MUST be silently ignored — no NOTIFICATION, no session termination | `src/message/open.rs`, `src/fsm/mod.rs` | ✅ | Added 2026-07-16 — unrecognized capability codes decode to `Capability::Unknown` (not an error); grepped the FSM/daemon for any special-casing of `Capability::Unknown` — none exists, it's inert data |
| NOTIFICATION error code 2 subcode 7 (Unsupported Capability) on mismatch | `src/message/` | ✅ | `test_unsupported_capability_notification` |
| §5: Data field of an Unsupported Capability NOTIFICATION MUST encode each capability "in the same way as it would be encoded in the OPEN message" (full Code/Length/Value, not just the code) | `src/fsm/mod.rs` `encode_unsupported_capabilities` | ✅ | Fixed 2026-07-30 (`fix/rfc5492-unsupported-capability-notification-data`, GH PR #43). `encode_unsupported_capabilities` now reuses `open::encode_capability_value` (made `pub(crate)`, re-exported via `message::mod.rs`) to emit the real `code(1) + length(1) + value` TLV for each capability, matching the OPEN-message encoding exactly rather than a `[code, 0x00]` placeholder. `test_unsupported_capability_notification_encodes_full_capability_tlv` uses `MultiProtocol(IPv6 unicast)` specifically because `RouteRefresh` (the existing test's capability) has a zero-length value and can't distinguish the old placeholder from the correct encoding. |
| Retry without capabilities (when peer's TCP response indicates it doesn't support capabilities advertisement at all) | `src/fsm/mod.rs` | ❌ | — corrected citation 2026-07-16: this deferred item previously described the trigger as "NOTIFICATION error 2/7" (Unsupported Capability), but that's the *wrong* scenario — subcode 7 is what *we* send when *we* require a capability the peer lacks, and RFC 5492 §3 says explicitly "If terminated, such peering SHOULD NOT be re-established automatically" for that case. The retry-without-capabilities behavior is actually keyed on receiving subcode **4** (Unsupported Optional Parameter — RFC 4271's own pre-existing mechanism, triggered when the *peer* doesn't understand the Capabilities Optional Parameter at all): "the speaker SHOULD attempt to re-establish a BGP connection with the peer without sending... the Capabilities Optional Parameter." Still unimplemented either way, but the description now points at the right trigger for whoever picks this up. |

**Deferred:** Retry-without-capabilities path (see corrected description above,
keyed on subcode 4, not 7) — not yet implemented.

---

## RFC 4760 — Multiprotocol Extensions for BGP-4 (Codec)

**Owns:** MP_REACH_NLRI (type 14) and MP_UNREACH_NLRI (type 15) encode/decode for all
AFI/SAFI combinations this daemon currently supports (IPv4 unicast, IPv6 unicast).  
**Boundary:** AFI/SAFI registry lives in `pathvector-types`. Daemon-level processing of
multiprotocol routes (inserting into AdjRibIn, propagating) lives in `pathvectord`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4760

| Requirement | File | Status | Verified by |
|---|---|---|---|
| MP_REACH_NLRI (type 14): AFI, SAFI, next-hop length, next-hop, SNPA, NLRI | `src/message/` | ✅ | `test_mp_reach_ipv6_roundtrip`, interop:gobgp |
| MP_UNREACH_NLRI (type 15): AFI, SAFI, withdrawn NLRI | `src/message/` | ✅ | `test_mp_unreach_ipv6_roundtrip` |
| IPv6 global unicast next-hop (16-byte form) | `src/message/` | ✅ | `test_mp_reach_ipv6_roundtrip` |
| IPv6 link-local next-hop (32-byte form: global + link-local) | `src/message/` | ✅ | `test_mp_reach_ipv6_link_local_roundtrip` |

---

## RFC 6793 — Four-Octet AS Number Capability

**Owns:** FourByteAsn capability (code 65) negotiation; AS_TRANS substitution in the 2-byte
`my_as` field when the local ASN exceeds 65535; the per-session ASN width (`AsnWidth`,
decided once from the OPEN exchange by `AsnWidth::negotiate`) and everything the wire codec
does with it — two- vs. four-octet `AS_PATH`/`AGGREGATOR` decode and encode, AS_TRANS +
generated `AS4_PATH`/`AS4_AGGREGATOR` toward an OLD peer, `AS4_PATH`/`AS4_AGGREGATOR`
reconstruction (§4.2.3) from an OLD peer, and discard of both from a NEW peer.  
**Boundary:** `Asn` type, `AS_TRANS` constant and the pure path-merge
(`AsPath::reconstruct_with_as4_path`) live in `pathvector-types`. Deciding *which routes'*
ASNs to downgrade (and building the AS4 attributes up front so UPDATE packing sees their
size) is `pathvectord/src/outbound.rs`; the codec guarantees the wire form regardless.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc6793

| Requirement | File | Status | Verified by |
|---|---|---|---|
| FourByteAsn capability (code 65) advertised in OPEN | `src/message/` | ✅ | `test_capability_four_byte_asn_in_open`, interop:gobgp |
| When local ASN > 65535, 2-byte `my_as` field set to AS_TRANS (23456) | `src/message/` | ✅ | `test_open_my_as_uses_as_trans_for_4byte_asn` |
| §4.1: width is bilateral — four-octet only if the capability is advertised to *and* received from the peer | `src/message/asn_width.rs`, `src/transport/mod.rs` | ✅ | `four_octets_only_when_both_sides_advertise_the_capability`, `legacy_peer_two_octet_as_path_is_announced_not_withdrawn` |
| §4.1/§4.2: `AS_PATH` decoded with two-octet ASNs from an OLD peer, four-octet from a NEW peer (issue #95) | `src/message/update.rs` `decode_as_path_segments` | ✅ | `issue_95_reproduction_two_octet_as_path_decodes_as_65002`, `multi_segment_legacy_path_is_not_misparsed_as_four_octet`, `all_four_segment_types_decode_at_two_octets`, `maximal_255_asn_segment_decodes_at_both_widths` |
| §4.2.2: `AS_PATH`/`AGGREGATOR` encoded with two-octet ASNs toward an OLD peer (writer half of the codec honours the width) | `src/framing/mod.rs`, `src/message/update.rs` | ✅ | `two_octet_session_encodes_two_octet_as_path`, `updates_to_a_legacy_peer_are_encoded_with_two_octet_asns` |
| §4.2.2: non-mappable ASN written as AS_TRANS; `AS4_PATH` generated (four-octet, confed segments excluded) unless every non-confed ASN is mappable | `src/message/update.rs` `append_missing_as4_attributes` | ✅ | `non_mappable_asn_becomes_as_trans_with_as4_path_generated`, `generated_as4_path_excludes_confed_segments`, `no_as4_path_when_every_asn_is_mappable`, `no_as4_path_when_only_confed_segments_are_non_mappable`, `caller_supplied_as4_path_is_not_duplicated` |
| §4.2.2: non-mappable aggregator → `AGGREGATOR` carries AS_TRANS plus `AS4_AGGREGATOR`; mappable → no `AS4_AGGREGATOR` | `src/message/update.rs` | ✅ | `non_mappable_aggregator_uses_as_trans_and_as4_aggregator`, `mappable_aggregator_is_six_bytes_with_no_as4_aggregator` |
| §4.1: `AS4_PATH`/`AS4_AGGREGATOR` never written on a four-octet session | `src/message/update.rs` `encode_path_attributes` | ✅ | `as4_attributes_are_never_sent_on_a_four_octet_session` |
| §4.1/§6: `AS4_PATH`/`AS4_AGGREGATOR` received from a NEW peer are discarded, the UPDATE continues, and the discard is reported for logging | `src/message/update.rs` `reconcile_as4_attributes` | ✅ | `as4_attributes_from_a_four_octet_peer_are_discarded_and_logged`, `four_octet_peer_keeps_four_octet_as_path_and_as4_path_is_discarded` |
| §4.2.3: reconstruct the true path from `AS_PATH` + `AS4_PATH` (shorter `AS4_PATH` prepended with leading `AS_PATH` hops; longer `AS4_PATH` ignored; leading/adjacent confed segments kept) | `pathvector-types` `AsPath::reconstruct_with_as4_path`, called from `reconcile_as4_attributes` | ✅ | `as4_path_is_merged_into_as_path_from_an_old_peer`, `as4_path_shorter_than_as_path_is_prefixed_with_the_leading_as_path_hops`, `as4_path_longer_than_as_path_is_ignored`, `leading_confed_segment_survives_the_merge`, types `reconstruct_*` |
| §4.2.3: `AGGREGATOR` vs `AS4_AGGREGATOR` — AS_TRANS ⇒ `AS4_AGGREGATOR` replaces it; otherwise `AS4_AGGREGATOR` *and* `AS4_PATH` are ignored | `src/message/update.rs` | ✅ | `as4_aggregator_replaces_an_as_trans_aggregator`, `non_trans_aggregator_makes_as4_aggregator_and_as4_path_ignored`, `lone_as4_aggregator_is_dropped` |
| §6: confed segments in a received `AS4_PATH` are discarded (not the attribute), logged, UPDATE continues — except `AS_CONFED_SET`, which RFC 9774 makes treat-as-withdraw | `src/message/update.rs` | ✅ | `confed_segments_in_as4_path_are_discarded_and_logged_not_fatal` |
| §6: malformed `AS4_PATH` (length < 6 or odd, zero-length segment, bad type, overrun) / `AS4_AGGREGATOR` (length ≠ 8) → attribute discard | `src/message/update.rs` | ✅ | `malformed_as4_path_is_attribute_discard_and_as_path_is_untouched`, `test_as4_aggregator_too_short_is_attribute_discard` |
| RFC 7606 §7.2: zero-length segment, unknown type, overrun, one-octet underrun in `AS_PATH` → treat-as-withdraw at either width | `src/message/update.rs` | ✅ | `rfc7606_*` in `asn_width_tests.rs` |
| RFC 4271 §4.3: a segment holds ≤ 255 ASNs — longer ones are split on encode, never truncated | `src/message/update.rs` `encode_as_path_segments` | ✅ | `oversized_sequence_splits_into_255_asn_segments_at_both_widths`, `prop_long_sequences_split_at_255_and_roundtrip` |
| Property: encode for an OLD peer then decode as an OLD peer recovers the true path/aggregator | `src/message/prop_tests.rs` | ✅ | `prop_two_octet_encode_then_decode_recovers_the_true_path_and_aggregator` |
| Live interop against a genuine two-octet-only speaker (e.g. GoBGP `--as2`) | — | ❌ | — |

**Known limits (inherent to RFC 6793, not defects):** a non-mappable ASN inside a
confederation segment cannot survive an OLD speaker (§4.2.2 excludes confed segments from
`AS4_PATH`; §7 forbids such Member-AS numbers); an `AS_SET` of more than 255 members cannot be
expressed exactly and is split into several sets on encode; adjacent same-type segments of a
merged path are only re-coalesced at the AS_PATH/AS4_PATH join.

**Deferred:** A live legacy-peer interop test. The unit, property and loopback-TCP tests
use hand-derived RFC bytes, but no real two-octet-only implementation has been run against
this code.

---

## RFC 7607 — Codification of AS 0 Processing

**Owns:** AS 0 in OPEN (both directions) and in received UPDATE attributes.  
**Boundary:** Not advertising AS 0 and rejecting it in configuration are
`pathvectord`'s. The encoder writes what it is given: a caller of
`SessionHandle::update_sender` is responsible for not originating AS 0.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc7607

| Requirement | File | Status | Verified by |
|---|---|---|---|
| §2: zero as the peer AS in an OPEN → NOTIFICATION OPEN Message Error / Bad Peer AS, whether or not a peer AS is expected; `my_as` or `FourByteAsn` | `src/fsm/mod.rs` `validate_open` | ✅ | `two_octet_open_claiming_as_zero_is_bad_peer_as`, `four_octet_capability_claiming_as_zero_is_bad_peer_as`, `expecting_as_zero_does_not_admit_it`, `prop_open_is_rejected_iff_it_claims_as_zero` |
| Repeated `FourByteAsn` capabilities: a zero in any instance is refused (no RFC defines which instance counts) | `src/fsm/mod.rs` `peer_speaker_as` | ✅ | `any_zero_among_repeated_capabilities_is_bad_peer_as` |
| RFC 6793 §4.1: a non-zero capability value supersedes `my_as = 0` | `src/fsm/mod.rs` | ✅ | `capability_value_supersedes_a_zero_my_as` |
| §2: "A router MUST NOT initiate a connection claiming to be AS 0" — `local_as`, `public_as` or the capability | `src/fsm/mod.rs` `local_speaker_as` | ✅ | `no_connection_is_initiated_while_claiming_as_zero`, `no_open_is_sent_if_the_claim_turns_to_as_zero_after_start` |
| §2: AS 0 in `AS_PATH` → treat-as-withdraw (RFC 7606 §7.2) | `src/message/as_rules.rs` | ✅ | `as_zero_anywhere_in_as_path_is_treat_as_withdraw`, `prop_as_path_verdict` |
| §2: AS 0 in `AGGREGATOR` → attribute discard (RFC 7606 §7.7) | `src/message/as_rules.rs` | ✅ | `as_zero_aggregator_is_discarded_and_the_route_kept`, `only_the_first_aggregator_is_judged` |
| §2: AS 0 in `AS4_PATH` / `AS4_AGGREGATOR` → attribute discard (RFC 6793 §6), applied before the §4.2.3 merge | `src/message/as_rules.rs` | ✅ | `as_zero_in_as4_path_discards_as4_path`, `as_zero_in_an_as4_path_confed_segment_discards_as4_path`, `as_zero_in_as4_aggregator_discards_as4_aggregator`, `as_zero_aggregator_from_a_two_octet_peer_leaves_as4_path_in_use` |

---

## RFC 9774 — Deprecation of AS_SET and AS_CONFED_SET

**Owns:** Treat-as-withdraw for received sets.  
**Boundary:** Not advertising sets is `pathvectord`'s. As above, the encoder
writes what it is given, and `MalformedUpdate::update` keeps the offending
attribute so it can be inspected.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc9774

| Requirement | File | Status | Verified by |
|---|---|---|---|
| §3: `AS_SET` / `AS_CONFED_SET` in `AS_PATH` → treat-as-withdraw | `src/message/as_rules.rs` | ✅ | `either_set_type_in_as_path_is_treat_as_withdraw`, `confed_set_after_a_confed_sequence_is_treat_as_withdraw`, `a_set_in_a_repeated_as_path_is_ignored`, `prop_as_path_verdict` |
| §3: the same in `AS4_PATH`, at either ASN width — stronger than RFC 6793's discard, so it applies (RFC 7606 §3(h)) | `src/message/as_rules.rs` | ✅ | `either_set_type_in_as4_path_is_treat_as_withdraw_at_either_width`, `set_and_as_zero_in_as4_path_is_treat_as_withdraw`, `confed_sequence_in_as4_path_is_still_only_discarded` |
| §3: operator exception for a transition period | — | ❌ | not offered (optional; see `TODO.md`) |

---

## RFC 6286 — Autonomous-System-Wide Unique BGP Identifier

**Owns:** Rejection of duplicate BGP ID from iBGP peers in `validate_open`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc6286

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Duplicate iBGP BGP-ID rejected with NOTIFICATION (OPEN error, Bad BGP Identifier) | `src/fsm/mod.rs` | ✅ | `test_duplicate_bgp_id_rejected`, interop:gobgp |

---

## RFC 4724 — Graceful Restart Mechanism for BGP

**Owns:** Graceful Restart capability (code 64) parsing and forwarding via `SessionInfo`.
The FSM restart behavior is deferred.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4724

| Requirement | File | Status | Verified by |
|---|---|---|---|
| GracefulRestart capability (code 64) parsed from OPEN | `src/message/` | ✅ | `test_capability_graceful_restart_parsed` |
| Capability forwarded to `SessionInfo` for upper layers | `src/fsm/mod.rs` | ✅ | `test_session_info_carries_graceful_restart` |
| Stale timer: retain routes for restart-time seconds during restart | — | ✅ | Owned by `pathvectord` (GR deadline timer in event loop) — see `pathvectord/RFC.md` |
| `TerminationReason` (Clean / Unclean) emitted on session close; upper layer uses it to decide GR eligibility | `src/transport/mod.rs` | ✅ | `test_termination_reason_notification_is_clean`, `test_termination_reason_tcp_failed_is_unclean`, `test_termination_reason_manual_stop_is_clean` |
| EOR (End-of-RIB) marker: empty UPDATE sent after RIB dump | — | ✅ | Owned by `pathvectord` — see `pathvectord/RFC.md` |

**Deferred:** §3 SHOULD: suppress GR capability when peer's restart_time = 0 (logged as warning in `pathvectord`; deferred).

---

## RFC 4486 — Subcodes for BGP Cease NOTIFICATION Message

**Owns:** All 10 Cease NOTIFICATION subcodes as named constants and enum variants.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4486

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Subcode 1: Maximum Number of Prefixes Reached | `src/message/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |
| Subcode 2: Administrative Shutdown | `src/message/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |
| Subcode 3: Peer De-configured | `src/message/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |
| Subcode 4: Administrative Reset | `src/message/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |
| Subcode 5: Connection Rejected | `src/message/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |
| Subcode 6: Other Configuration Change | `src/message/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |
| Subcode 7: Connection Collision Resolution | `src/message/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |
| Subcode 8: Out of Resources | `src/message/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |
| Subcode 9: Hard Reset | `src/message/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |
| Subcode 10: BFD Down | `src/message/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |

---

## RFC 6608 — Subcodes for BGP Finite State Machine Error

**Owns:** FSM error subcodes 0 (Unspecified), 1 (Unexpected message in OpenSent),
2 (Unexpected message in OpenConfirm), 3 (Unexpected message in Established).  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc6608

| Requirement | File | Status | Verified by |
|---|---|---|---|
| FSM error subcode 0: Unspecified Error | `src/message/notification.rs` | ✅ | `test_fsm_error_subcodes_all_defined` |
| FSM error subcode 1: Receive Unexpected Message in OpenSent State | `src/fsm/mod.rs` | ✅ | `test_fsm_error_subcodes_all_defined`, `test_unexpected_message_in_open_sent_sends_fsm_error_subcode_1` |
| FSM error subcode 2: Receive Unexpected Message in OpenConfirm State | `src/fsm/mod.rs` | ✅ | `test_fsm_error_subcodes_all_defined`, `test_unexpected_message_in_open_confirm_sends_fsm_error_subcode_2` |
| FSM error subcode 3: Receive Unexpected Message in Established State | `src/fsm/mod.rs` | ✅ | `test_fsm_error_subcodes_all_defined`, `test_unexpected_message_in_established_sends_fsm_error_subcode_3` |
| §4: the FSM Error NOTIFICATION's Data is "a 1-octet, unsigned integer that indicates the type of the unexpected message" (all three states) | `src/fsm/mod.rs`, `src/message/mod.rs` (`BgpMessage::type_code`) | ✅ | Fixed (PR #143 review, Codex): Data was empty. `rfc6608_4_fsm_error_data_is_the_unexpected_message_type`; matrix tests assert `[2]` for UPDATE; real-TCP `open_sent_update_of_every_recovery_outcome_is_an_fsm_error_with_no_route_event` / `open_confirm_…` decode it off the wire |

---

## RFC 8654 — Extended Message Support for BGP

**Owns:** ExtendedMessage capability (code 6); raising the message size limit from 4096 to
65535 bytes when both peers negotiate the capability.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc8654

| Requirement | File | Status | Verified by |
|---|---|---|---|
| ExtendedMessage capability (code 6) decoded from OPEN | `src/message/` | ✅ | `test_capability_extended_message_parsed` |
| Message size limit raised to 65535 when both peers advertise capability | `src/message/` | ✅ | `test_extended_message_limit_applies_when_negotiated`, interop:gobgp |
| Message size limit stays at 4096 when capability not negotiated | `src/message/` | ✅ | `test_message_limit_4096_without_extended_message_cap` |

---

## RFC 2385 — Protection of BGP Sessions via MD5

**Datatracker:** https://datatracker.ietf.org/doc/html/rfc2385

| Requirement | File | Status | Verified by |
|---|---|---|---|
| `TCP_MD5SIG` key installed on outbound socket before `connect()` | `transport/mod.rs` `tcp_connect` | ✅ | `key_is_installed_before_connecting` |
| Key that cannot be enforced, with `Md5Enforcement::Required` (default): no connection attempt, `ErrorKind::Unsupported` (RFC 5925 §8: required MD5 "must be added to all outgoing segments and validated on all incoming segments"; issue #58) | `transport/tcp_md5.rs` `protect_socket` | ✅ | `required_key_that_cannot_be_enforced_is_an_error`, `required_but_unenforceable_never_connects` |
| `Md5Enforcement::BestEffort` is an explicit opt-in; connects unauthenticated, logs a warning, returns `Md5Protection::Unenforced(reason)` | `transport/tcp_md5.rs` | ✅ | `best_effort_reports_unenforced_with_reason`, `best_effort_connects_when_unenforceable` |
| `BestEffort` does not hide real `setsockopt` failures | `transport/tcp_md5.rs` | ✅ | `best_effort_does_not_hide_os_errors` |
| `TCP_MD5SIG` key on the BGP listening socket for each configured peer, installed before `listen()` (RFC 5925 §8: required MD5 "validated on all incoming segments"; issue #66) | `transport/listener.rs` `BgpListener::bind`, `pathvectord` `run_bgp_listener` | ✅ | `key_configured_before_bind_is_installed_before_listen`, `static_key_admits_only_the_matching_key` (live, CI), `static_peer_inbound_requires_the_key` |
| Keys added, rotated and removed on the live listening socket; after an add or rotation the socket is replaced, with every key installed before `listen()` | `transport/listener.rs` `ListenerKeys::{set_peer, remove_peer}`, `pathvectord` `run_command_processor` | ✅ | `dynamically_added_key_is_enforced`, `rotated_key_replaces_the_old_one`, `removed_key_is_no_longer_enforced` (live, CI), `key_change_replaces_the_socket_with_keys_installed_before_listen`, `add_peer_installs_listener_key_before_routing_inbound`, `remove_peer_removes_the_listener_key`, `dynamic_peer_inbound_requires_the_key_until_removed` |
| A connection that completed before a key change carries no key (Linux copies the key at `tcp_v4_syn_recv_sock`); it is closed, not handed over. Barrier: the old socket is shut down (`tcp_disconnect` → `inet_csk_listen_stop`; a late `inet_csk_reqsk_queue_add` sees `sk_state != TCP_LISTEN`) | `transport/listener.rs` `BgpListener::{accept, replace_socket}` | ✅ | `connection_queued_before_a_new_key_is_rejected`, `rotation_installs_the_new_key_and_replaces_the_socket`, `connection_completed_before_a_dynamic_key_is_rejected` (live, CI) |
| A connection screened before its peer's key was set (buffered while replacing the socket, or accepted just before `AddPeer`) is never used | `transport/listener.rs` `AuthStamp`, `ListenerKeys::is_current`; `pathvectord` `route_inbound` | ✅ | `buffered_connection_is_dropped_when_its_peer_gains_a_key`, `buffered_connection_is_dropped_when_its_peers_key_is_refused`, `accepted_connection_stops_being_current_when_its_peer_gains_a_key`, `connection_accepted_before_add_peer_is_not_routed_to_the_new_session` |
| Listener key that cannot be enforced under `Required`, or any `setsockopt` failure: the peer's inbound connections are closed; `BestEffort` admits them unauthenticated with a warning | `transport/listener.rs` | ✅ | `required_key_that_cannot_be_enforced_rejects_the_peer`, `os_error_rejects_even_a_best_effort_peer`, `best_effort_key_that_cannot_be_enforced_admits_unauthenticated`, `required_key_on_a_host_without_md5_rejects_the_peer` (live), `add_peer_with_unenforceable_required_key_refuses_inbound` |
| `md5_password` TOML field validated (1–80 bytes) and wired into `SessionConfig::tcp_md5` | `pathvectord` `config.rs`, `daemon/` | ✅ | `test_md5_password_empty_is_rejected`, `test_md5_password_over_80_bytes_is_rejected`, `build_daemon_md5_password_reaches_session_config` |

**Platform note:** keys are only enforced on Linux kernels built with
`CONFIG_TCP_MD5SIG`, for IPv4 peers. Elsewhere `pathvector-sys` reports
`TcpMd5Error::Unsupported` and the session applies its `Md5Enforcement` policy.
The kernel-level proof (matching keys connect; unsigned and wrong-key SYNs are
dropped) is `pathvector-sys/tests/tcp_md5_loopback.rs` for the raw adapter and
`pathvector-session/tests/listener_md5_loopback.rs` for `BgpListener`.

---

## RFC 9234 — Route Leak Prevention Using Roles in UPDATE and OPEN Messages

**Owns:** BGP Role capability (code 9) encode/decode; role-pair correctness
validation during OPEN exchange (`validate_open`); NOTIFICATION subcode 11
(Role Mismatch); the `ONLY_TO_CUSTOMER` path attribute (type 35) encode/decode.  
**Boundary:** Per-peer `Role` configuration lives in `pathvectord`. OTC-driven
route-leak *policy* (reject-on-leak, attach-on-ingress/egress) lives in
`pathvector-policy`; this crate only carries the role/attribute on the wire and
enforces role-pair compatibility at session-establishment time.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc9234

| Requirement | File | Status | Verified by |
|---|---|---|---|
| BGP Role capability (code 9): 1-byte value, roles 0–4 | `src/message/open.rs` | ✅ | `test_role_capability_roundtrip_all_defined_values` |
| Unrecognized role value (5–255) decodes without erroring | `src/message/open.rs` | ✅ | `test_role_capability_unrecognized_value_decodes_as_unknown` |
| Truncated Role capability body is a decode error, not a panic | `src/message/open.rs` | ✅ | `test_truncated_role_capability_is_error` |
| Role-pair correctness at OPEN exchange (Provider↔Customer, RS↔RS-Client, Peer↔Peer) | `src/fsm/mod.rs` `validate_open` | ✅ | `test_role_pair_matrix` (25 combinations) |
| Non-strict default: Role absent on either side is not a mismatch | `src/fsm/mod.rs` `validate_open` | ✅ | `test_role_absent_on_peer_side_is_not_a_mismatch`, `test_role_absent_locally_is_not_a_mismatch` |
| NOTIFICATION code 2 subcode 11 (Role Mismatch) on incompatible pairs | `src/message/notification.rs` | ✅ | `test_role_mismatch_encodes_as_code_2_subcode_11` |
| `ONLY_TO_CUSTOMER` attribute (type 35), optional+transitive (flags `0xC0`), 4-byte ASN | `src/message/update.rs` | ✅ | `test_only_to_customer_roundtrip`, `test_only_to_customer_encodes_as_optional_transitive` |
| Malformed-length OTC handling | `src/message/update.rs` | ❌ | **Corrected 2026-07-16 by `RFC_AUDIT.md`** — this row previously claimed ✅ for falling through to `AttributeDiscard`, but RFC 9234 §5 states explicitly: "An UPDATE message with a malformed OTC Attribute SHALL be handled using the approach of 'treat-as-withdraw' [RFC7606]" — not attribute-discard. `rfc7606_policy()` (`update.rs:60-71`) doesn't special-case `ATTR_ONLY_TO_CUSTOMER`, so it falls into the generic `_ => AttributeErrorPolicy::AttributeDiscard` arm alongside ordinary optional attributes. Security-relevant: a malformed-length OTC is silently dropped and the route is otherwise accepted and processed normally (as if OTC had never been present), rather than the whole route being withdrawn — this is a plausible evasion path around the leak-detection mechanism this RFC exists to provide, since a route that should have been caught by `OtcLeakCondition` could instead sail through untagged if its OTC attribute is deliberately malformed. See `RFC_AUDIT.md`'s RFC 9234 section. |
| Peer sends multiple/conflicting BGP Role Capability instances | `src/fsm/mod.rs` `validate_open` | ❌ | Added 2026-07-16 by `RFC_AUDIT.md`. RFC 9234 §4.2 requires: identical duplicate Role Capabilities are treated as one (fine); Role Capabilities with **differing** values MUST cause the connection to be rejected with Role Mismatch. `validate_open`'s `peer.capabilities.iter().find_map(...)` (`fsm/mod.rs:712-715`) takes only the **first** `Capability::Role` and silently ignores any subsequent ones, including differing ones — the exact same code shape as the RFC 4724 GR "first instance" bug found in the prior audit pass. A peer sending two different Role values would never be detected or rejected. |

**Deferred:** Strict mode (reject when only one side advertises Role) — the RFC makes
this optional and non-default; tracked as a non-blocking follow-up in `TODO.md`.
AS-confederation-aware OTC — the RFC itself says NOT RECOMMENDED, matching this
project's existing confederation scope boundary.

---

## RFC 5065 — AS Confederations for BGP (Session Layer)

**Owns:** `FsmConfig.confederation_member` / `SessionConfig.confederation_member` —
the per-session flag that makes `Fsm::build_session_info` classify the peer as
`PeerType::ConfedMember` instead of `PeerType::External`. This is the
**authoritative** classification for every live Established session; a
daemon-side classifier alone would only cover the pre-Established/
post-disconnect windows. Also owns `FsmConfig.public_as` /
`SessionConfig.public_as` — the AS number `make_open` places in the OPEN
message's `my_as` field, resolved by the caller (`pathvectord`) per RFC 5065
§4 ("MUST use its AS Confederation Identifier in all transactions with peers
that are not members of its confederation... this number is used in OPEN
messages... MUST use its Member-AS Number in all transactions with peers
that are members of the same confederation").  
**Boundary:** AS_PATH segment types, `strip_confed_segments()`, and
`prepend_confed()` live in `pathvector-types`. Confederation config schema
(`confederation_id`, `confederation_member`), best-path/outbound handling, and
the RFC 5065 §5 malformed-AS_PATH import checks all live in `pathvectord`/
`pathvector-rib` — this crate's decoder has no visibility into which peer
sent an UPDATE relative to confederation membership, so those relationship-
dependent checks cannot live here.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc5065

| Requirement | File | Status | Verified by |
|---|---|---|---|
| `Fsm::build_session_info` classifies `ConfedMember` when `confederation_member` is set and `peer_as != local_as` | `src/fsm/mod.rs` | ✅ | `test_session_info_confed_member_peer_type_when_configured` |
| `local_as == peer_as` still classifies `Internal` even if `confederation_member` is also set | `src/fsm/mod.rs` | ✅ | `test_session_info_same_as_wins_over_confed_member` |
| `make_open`'s `my_as` (and the caller-supplied `FourByteAsn` capability) uses `public_as`, not `local_as` — required so a genuinely `External` session under a configured confederation advertises the Confederation Identifier, not the private Member-AS Number (RFC 5065 §4) | `src/fsm/mod.rs` | ✅ | `test_sent_open_uses_public_as_not_local_as` |

Shipped 2026-08-04 (`feature/rfc5065-confederation-member-support`). Real-teeth
verified: reverted the fix, confirmed
`test_session_info_confed_member_peer_type_when_configured` failed with
`left: External, right: ConfedMember`, then restored and reran the full
343-test suite green.

**Fixed 2026-08-05** after external code review of PR #51 found that
external OPENs still advertised the private Member-AS Number, not the
Confederation Identifier — RFC 5065 §4's OPEN-message requirement had only
been applied to AS_PATH generation, not to the session's own `my_as`/
`FourByteAsn` capability. Added `FsmConfig.public_as`/`SessionConfig.public_as`,
resolved by `pathvectord` (`effective_session_as`) at every session-spawn
and reconnect-capability-refresh call site. Real-teeth verified: reverted
`make_open` to use `local_as`, confirmed `test_sent_open_uses_public_as_not_local_as`
failed (`left: 65001, right: 64512`), then restored and reran the full
344-test suite green.

**End-to-end coverage (2026-08-05, `pathvector-e2e`):** the unit test above
proves `make_open` picks the right field; it doesn't prove a real
implementation on the other end of the wire actually accepts it.
`ConfederationHarness`'s
`confederation_sessions_establish_with_correct_visible_as` (see
`pathvectord/RFC.md`'s RFC 5065 section for the full 3-node topology)
peers pathvectord against a real GoBGP process configured to expect the
Confederation Identifier — a `public_as` regression would make that
session fail to establish (Bad Peer AS) while an otherwise-identical
Member-AS session to FRR still came up fine, so this test would have
caught the original finding directly.

# RFC Requirements — pathvector-rpki

This crate owns the RTR (RPKI-to-Router) protocol client and the resulting ROA validity
cache. It does not own RPKI repository sync, certificate validation, or policy
enforcement — see **Boundary** notes per RFC below.

**Status key:** ✅ Implemented and tested | ⚠️ Partial — see notes | ❌ Not started
**Verified by key:** `test_name` — unit test | `proptest` — property test | `interop:x` —
interop test | `—` — no automated verification

---

## RFC 8210 — The RPKI-to-Router Protocol, Version 1

**Owns:** Session lifecycle to an RTR server; PDU codec; version negotiation with RFC
6810 fallback; ROA cache population from Serial/Reset Query responses.
**Boundary:** Does not perform RPKI repository sync (rsync/RRDP) or certificate
validation — consumes already-validated ROA data from an external validator over RTR.
Router Key PDUs (BGPsec) are decoded-and-discarded, not acted upon (out of scope: no
BGPsec support in `pathvector-session`).
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc8210

| Requirement | File | Status | Verified by |
|---|---|---|---|
| PDU header framing (version, type, field, length) | `src/pdu.rs` | ✅ | `truncated_header_errors_never_panics`, `unknown_pdu_type_errors`, `unknown_version_errors` |
| Serial Notify / Serial Query / Reset Query PDUs | `src/pdu.rs` | ✅ | `serial_notify_roundtrip`, `serial_query_roundtrip`, `reset_query_roundtrip`, `proptest: serial_query_roundtrips` |
| Cache Response / Cache Reset PDUs | `src/pdu.rs` | ✅ | `cache_response_roundtrip`, `cache_reset_roundtrip` |
| IPv4/IPv6 Prefix PDUs (announce/withdraw) | `src/pdu.rs` | ✅ | `ipv4_prefix_announce_roundtrip`, `ipv4_prefix_withdraw_roundtrip`, `ipv6_prefix_roundtrip`, `proptest: ipv4_prefix_roundtrips`, `proptest: ipv6_prefix_roundtrips` |
| End of Data PDU (v1: with refresh/retry/expire intervals) | `src/pdu.rs` | ✅ | `end_of_data_v1_roundtrip`, `end_of_data_v1_is_longer_than_v0`, `proptest: end_of_data_v1_roundtrips` |
| Error Report PDU | `src/pdu.rs` | ✅ | `error_report_roundtrip`, `error_report_empty_fields_roundtrip`, `error_report_invalid_utf8_text_errors` |
| Router Key PDU (decode-and-discard; no BGPsec use) | `src/pdu.rs` | ✅ | `router_key_decodes_and_is_discarded` |
| Session establishment: Reset Query on first connect | `src/client.rs` | ✅ | `full_sync_populates_table_and_status` |
| Incremental update: Serial Query with last known serial | `src/client.rs` | ✅ | `sync_once` (unit-level; covered indirectly by the idle-loop path in `full_sync_populates_table_and_status`) |
| Session ID validation: Cache Response to a Serial Query (§5.5), End of Data vs its Cache Response (§5.8), Serial Notify (§5.2) — mismatch ⇒ Error Report 0 and flush (§5.1) | `src/protocol.rs`, `src/client.rs` | ✅ | `cache_response_with_other_session_id_to_serial_query_is_rejected_and_flushed`, `idle_serial_notify_with_other_session_id_flushes_with_error_0`, `end_of_data_session_mismatch_flushes_old_and_staged_data_with_one_notification`, unit: `cache_response_with_other_session_to_serial_query_is_corrupt_data`, `end_of_data_must_match_the_cache_response_session` (#90) |
| Protocol version stable once negotiated (§7); every PDU of a transfer and every idle Serial Notify must carry it, else Error Report 8; End of Data must match its Cache Response's version (§5.8); v0 answer to a v1 resume is a separate session (§5.1) | `src/protocol.rs`, `src/client.rs` | ✅ | `cache_response_at_other_version_after_negotiation_drops_session_with_error_8`, `prefix_pdu_at_other_version_mid_transfer_drops_session_with_error_8`, `end_of_data_at_other_version_publishes_nothing`, `idle_serial_notify_at_other_version_drops_session_with_error_8`, `resume_answered_at_lower_version_is_a_new_session_and_forces_full_resync` (#90) |
| Serial Notify ignored during version negotiation, whatever its version (§7) | `src/protocol.rs` | ✅ | `serial_notify_during_version_negotiation_is_ignored`, unit: `serial_notify_is_ignored_during_negotiation_whatever_its_version_or_session` (#90) |
| §8.3 Cache Reset as the reply to a Serial Query ⇒ Reset Query on the same connection; resume state forgotten at once; Cache Reset in reply to a Reset Query, or after a Cache Response (§5.9), is a violation | `src/protocol.rs`, `src/client.rs` | ✅ | `cache_reset_in_reply_to_serial_query_triggers_reset_query_on_same_connection`, `reconnect_after_cache_reset_opens_with_reset_query_not_serial_query`, `cache_reset_mid_incremental_transfer_publishes_nothing` (#87). Replaces `cache_reset_mid_stream_triggers_full_resync_on_same_connection`, which cited §5.7 (IPv6 Prefix) and asserted a Cache-Reset-after-Cache-Response behaviour no RFC 8210 clause defines |
| §4/§5.8 completed-response semantics: VRPs, serial, status and `subscribe()` notification change together at End of Data; a failed transfer leaves the previous generation and its resume point intact | `src/cache.rs` | ✅ | `eof_mid_incremental_transfer_publishes_nothing`, `malformed_pdu_mid_incremental_transfer_publishes_nothing`, `interrupted_full_load_keeps_previous_vrps_and_publishes_nothing`, `incremental_transfer_is_published_atomically_at_end_of_data`, `full_reload_is_published_atomically_at_end_of_data` (#88) — a design choice made for the `subscribe()` contract; RFC 8210 does not mandate transactional application |
| §6 Refresh/Retry/Expire timers: advertised values override configured ones (v1), configured apply to v0, advertised values clamped to the RFC ranges, `RtrConfig::validate` | `src/timers.rs`, `src/client.rs` | ✅ | unit: `v1_advertised_values_replace_configured_ones`, `out_of_range_values_are_clamped_to_the_rfc_ranges`, `v0_uses_the_configured_timers`; `RtrConfig::validate` tests (#86) |
| §6 Expire Interval: "The router MUST NOT retain the data past the time indicated", counted from End of Data, unaffected by connection/query/notification activity; at expiry VRPs and resume state are discarded, status updated, subscribers notified | `src/cache.rs` (`watch_expiry`), `src/client.rs` | ✅ | `vrps_are_kept_until_the_advertised_expire_interval_then_removed`, `stalled_query_and_notifications_do_not_extend_expiry`, `no_data_available_responses_do_not_renew_expiry`, `expiry_fires_during_disconnect_and_reconnect_backoff`, `completed_update_renews_the_deadline`, `v0_session_expires_after_the_configured_interval`, `v1_advertised_expire_{shorter,longer}_than_configured_wins`, `out_of_range_advertised_expire_is_clamped_to_the_rfc_minimum`, `incremental_transfer_in_flight_at_expiry_is_not_applied_to_the_flushed_cache` (#86; paused-clock tests). At expiry every validation result is `NotFound` |
| Reconnect with retry-interval backoff on failure | `src/client.rs` | ✅ | `disconnect_mid_sync_reports_disconnected_without_clearing_table` |
| Unsolicited Serial Notify triggers immediate resync | `src/client.rs` | ✅ | `unsolicited_serial_notify_triggers_immediate_resync_not_timer_wait` |
| Version-mismatch adoption without an Error Report (§5: a v0-only cache "responds with a version 0 response") | `src/client.rs` | ✅ | `server_silently_replies_at_v0_without_error_report`, `adopted_version_is_used_for_subsequent_queries` |
| PDU length bound (reject before allocating, not just after) | `src/client.rs` | ✅ | `oversized_pdu_length_is_rejected_without_allocating` |
| §12/§8.4: Error Code 2 ("No Data Available") is explicitly non-fatal — session should stay usable, router MUST issue periodic **Reset Queries** (not a repeat of whatever query failed) until it gets a new usable load — distinct from the other 8 error codes, all explicitly marked "(fatal): ... MUST cause the session to be dropped" | `src/protocol.rs`, `src/client.rs` | ✅ | `error_code_2_no_data_available_retries_on_same_connection`, `error_code_2_after_serial_query_forces_reset_query`, `no_data_available_responses_do_not_renew_expiry` (fixed 2026-07-19, `fix/rfc8210-error-code-2-no-data-available`) — `Step::NoDataAvailable` (decided in `protocol.rs`, acted on in `client.rs::sync`) for `error_code == 2` sets a `force_reset` flag so the *next* query is always a genuine `ResetQuery`, regardless of remembered serial/session state, on the same connection after `retry_interval` (or the cache-advertised `EndOfDataIntervals.retry`, once a v1 session has supplied one, per §6). The stale table is retained until the forced Reset Query's replacement load *commits at End of Data* — not cleared the instant the error is received (nor, since #88, while the load is still streaming) — so a long retry window doesn't create an unnecessary no-data gap; every other error code still falls through to the generic fatal-error `Err` path |

**Deferred:** SSH transport (TCP-only; validators typically run on a loopback/internal
network). ASPA (RFC 9582) — separate RFC, out of scope entirely for ROV.

---

## RFC 6810 — The RPKI-to-Router Protocol (Version 0)

**Owns:** Fallback wire format for validators that don't support RTR v1 (notably: v0's
End of Data PDU omits the refresh/retry/expire fields present in v1).
**Boundary:** Same crate as RFC 8210 — v0 support is a decode/encode branch in
`src/pdu.rs`, not a separate implementation.
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc6810

| Requirement | File | Status | Verified by |
|---|---|---|---|
| V0 End of Data PDU (session_id + serial only, no intervals) | `src/pdu.rs` | ✅ | `end_of_data_v0_roundtrip_omits_intervals` |
| Version negotiation: v1 attempted first, falls back to v0 on Error Report (only while negotiating; once agreed the version is stable) | `src/client.rs` | ✅ | `v1_rejected_falls_back_to_v0_and_completes_sync` |

---

## RFC 6811 — BGP Prefix Origin Validation

**Owns:** The `validate(prefix, prefix_len, origin_asn) -> Valid/Invalid/NotFound`
algorithm (§2) against the cached ROA set, and (as of Phase 2) the policy-layer
`RoaValidityCondition` in `pathvector-policy` that consumes it to filter routes.
**Boundary:** This crate computes validity; `pathvector-policy` decides what to do with
it (`RoaValidityCondition` + `Reject`); `pathvectord` wires that term into every peer's
import policy (`DaemonState::install_rpki_import_terms`, gated by
`[daemon.rpki].reject_invalid`, default `true`).
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc6811

| Requirement | File | Status | Verified by |
|---|---|---|---|
| §2 validation algorithm (covering-ROA search, not just longest match) | `src/table.rs` | ✅ | `less_specific_roa_can_validate_when_more_specific_does_not`, `multiple_overlapping_roas_no_match_is_invalid_not_not_found`, `proptest: family_table_agrees_with_naive_model` |
| Multiple ROAs at the same prefix (different max-length/ASN) | `src/table.rs` | ✅ | `multiple_roas_at_same_prefix_any_match_wins`, `withdraw_of_one_of_several_leaves_others_intact` |
| IPv4 and IPv6 | `src/table.rs` | ✅ | `v6_exact_match_is_valid`, `v6_exceeds_max_len_is_invalid`, `v6_disjoint_is_not_found`, `roa_table_dispatches_v4_and_v6_independently` |
| Policy-layer filtering: reject `Invalid`, accept `Valid`/`NotFound` (RFC 7115 / BIRD / FRR convention) | `pathvector-policy/src/rpki.rs`, `pathvectord/src/daemon/mod.rs` | ✅ | `pathvector-policy`: `matches_invalid_on_wrong_origin_asn`, `uncovered_prefix_is_not_found_not_invalid`, `end_to_end_through_policy_invalid_rejected_others_fall_to_default`; `pathvectord`: `test_rov_accepts_route_with_valid_roa`, `test_rov_rejects_route_with_invalid_roa_wrong_origin_asn`, `test_rov_accepts_route_with_no_covering_roa`, `test_rov_not_installed_invalid_route_still_accepted` |
| §2 "Route Origin ASN" derivation: final AS_PATH segment determines it — `AS_SEQUENCE` final ⇒ its rightmost ASN; `AS_CONFED_SEQUENCE`/`AS_CONFED_SET` final, or empty path ⇒ **substitute the local speaker's own AS number**; any other final segment type (e.g. terminal `AS_SET`) ⇒ the "NONE" sentinel, never matches | `pathvector-types/src/aspath.rs` `AsPath::origin_as` | ✅ | Fixed 2026-07-19 (`fix/rfc6811-origin-as-confederation-segments`). `origin_as` now takes `local_as: Asn` and matches directly on `self.segments.last()` — no more backward search past the final segment. `RoaValidityCondition` (the one production caller, in `pathvector-policy/src/rpki.rs`) gained a `local_as` field, threaded from `pathvectord`'s `install_rpki_import_terms`. Tests: `test_aspath_origin_as_confed_sequence_final_substitutes_local_as`, `test_aspath_origin_as_confed_set_final_substitutes_local_as`, `test_aspath_origin_as_set_final_is_none`, `test_aspath_new_is_empty` (all four real-teeth verified — failed against the pre-fix backward-search logic, passed once fixed, failed again when temporarily reverted). Also corrected `empty_as_path_never_matches_and_never_panics` in `pathvector-policy/src/rpki.rs`, which had codified the old (wrong) "locally originated routes are exempt from ROV" behavior — per the RFC, an empty AS_PATH now genuinely validates against `local_as`, a real, intentional behavior change from before this fix. |
| §2 "NONE" origin (terminal `AS_SET`) must still resolve Invalid-vs-NotFound via VRP coverage, not be treated as blanket-exempt from ROV | `pathvector-policy/src/rpki.rs`, `pathvector-rpki/src/table.rs` | ✅ | Caught by Codex's review of the row above's own PR. `RoaValidityCondition::matches` used to short-circuit to `false` on a `None` origin, silently exempting terminal-`AS_SET` routes from ROV instead of applying "at least one VRP Covers but none Matches ⇒ Invalid". Fixed by routing the "NONE" case through the normal lookup using ASN `0` — the same sentinel RFC 6811 §2's own pseudo-code uses ("no Route can be Matched by a VRP whose ASN is zero") — with `RoaTable::validate` (`table.rs`) gaining an explicit `e.asn != 0` guard so this is enforced structurally, not just assumed. Tests: `terminal_as_set_origin_none_is_invalid_when_covered_by_a_roa`, `terminal_as_set_origin_none_is_not_found_when_uncovered` (real-teeth verified against the pre-fix short-circuit). |

**Deferred:** `routemap::covering_matches()` — a native API that would let `validate()`'s
ancestor walk collapse to a single trie traversal; tracked in `TODO.md` as a
non-blocking optimization, not a correctness gap.

**Bug fixed 2026-07-02:** `pathvectord::set_import_default` (the gRPC-triggered
`PolicyService` handler) used to fully replace the peer's `Policy`
(`Policy::new(action)`), silently discarding the installed ROV reject term along
with any other terms — found while auditing the equivalent RFC 9234 OTC exposure.
Any operator call to `pathvector peer set-import-default` on a peer would have
silently disabled ROV for it. Fixed by adding `Policy::set_default` (changes only
the default action, leaves terms untouched) and using it instead. See
`pathvectord/RFC.md`'s RFC 9234 section for the fuller writeup. Direct regression
test: `test_set_import_default_preserves_rpki_rov_term` (a ROV-only peer with no
`role` configured, proving the fix isn't OTC-specific).

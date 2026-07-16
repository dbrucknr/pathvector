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
| Session ID validation on End of Data | `src/client.rs` | ✅ | `session_id_mismatch_on_end_of_data_clears_table_and_errors` |
| Cache Reset handling (full resync) | `src/client.rs` | ✅ | `cache_reset_mid_stream_triggers_full_resync_on_same_connection` |
| Refresh/retry/expire interval timers, server-advertised override | `src/client.rs` | ✅ | `full_sync_populates_table_and_status` (refresh applied); retry/expire covered by `RtrConfig`/`RtrStatus::is_stale` |
| Reconnect with retry-interval backoff on failure | `src/client.rs` | ✅ | `disconnect_mid_sync_reports_disconnected_without_clearing_table` |
| Unsolicited Serial Notify triggers immediate resync | `src/client.rs` | ✅ | `unsolicited_serial_notify_triggers_immediate_resync_not_timer_wait` |
| Version-mismatch adoption without an Error Report (§5: a v0-only cache "responds with a version 0 response") | `src/client.rs` | ✅ | `server_silently_replies_at_v0_without_error_report`, `adopted_version_is_used_for_subsequent_queries` |
| PDU length bound (reject before allocating, not just after) | `src/client.rs` | ✅ | `oversized_pdu_length_is_rejected_without_allocating` |
| §12: Error Code 2 ("No Data Available") is explicitly non-fatal — session should stay usable, router should retry with periodic Reset Queries — distinct from the other 8 error codes, all explicitly marked "(fatal): ... MUST cause the session to be dropped" | `src/client.rs` | ❌ | Added 2026-07-16 by `RFC_AUDIT.md`. The `Pdu::ErrorReport` match in the query-response loop (lines 443-460) only special-cases `ERROR_CODE_UNSUPPORTED_PROTOCOL_VERSION`; every other code, including 2, falls through to a uniform `return Err(RtrError::ErrorReported {...})`. Likely still eventually resyncs via the existing generic reconnect-with-backoff path, but doesn't honor the RFC's specific intent of *not* tearing down the session for this one non-fatal case. See `RFC_AUDIT.md`'s RFC 8210 section. |

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
| Version negotiation: v1 attempted first, falls back to v0 on Error Report | `src/client.rs` | ✅ | `v1_rejected_falls_back_to_v0_and_completes_sync` |

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
| §2 "Route Origin ASN" derivation: final AS_PATH segment determines it — `AS_SEQUENCE` final ⇒ its rightmost ASN; `AS_CONFED_SEQUENCE`/`AS_CONFED_SET` final, or empty path ⇒ **substitute the local speaker's own AS number**; any other final segment type (e.g. terminal `AS_SET`) ⇒ the "NONE" sentinel, never matches | `pathvector-types/src/aspath.rs` `AsPath::origin_as` | ❌ | Added 2026-07-16 by `RFC_AUDIT.md`. `origin_as()` is `.iter().rev().find_map(\|seg\| match seg { Sequence(asns) => asns.last().copied(), _ => None })` — it searches **backward past** `Set`/`ConfedSequence`/`ConfedSet` segments for the nearest earlier plain `Sequence`, rather than applying the RFC's specific substitution (local ASN) or sentinel ("NONE") rules for those cases. Concretely wrong for AS_PATHs ending in a confederation segment — a real, supported scenario given this project's RFC 5065 confederation support — where the wrong AS number gets checked against the VRP database, which can flip a Valid/Invalid/NotFound verdict either way. This function isn't RPKI-specific (also used by `pathvector-rib/adj_rib_in.rs` and `pathvector-policy/action.rs`), so the fix needs care beyond just the ROV call site. See `RFC_AUDIT.md`'s RFC 6811 section for the full detail. |

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

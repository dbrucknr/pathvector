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
| UPDATE message encode/decode: withdrawn-routes, path-attributes, NLRI | `src/message/` | ✅ | `test_update_roundtrip`, `test_update_empty`, interop:gobgp |
| NOTIFICATION message encode/decode: error-code, error-subcode, data | `src/message/` | ✅ | `test_notification_roundtrip`, `test_notification_cease` |
| KEEPALIVE message encode/decode (header only, no body) | `src/message/` | ✅ | `test_keepalive_roundtrip` |
| Attribute flags: Optional, Transitive, Partial, Extended-Length — wire encode/decode round-trip | `src/message/` | ✅ | `test_attribute_flags_roundtrip`, `test_extended_length_attribute` |
| Attribute flags: reject a *received* attribute whose flags don't match what its type requires (well-known ⇒ Transitive=1; well-known/optional-non-transitive ⇒ Partial=0) — "Attribute Flags Error", UPDATE Message Error subcode 4 | `src/message/update.rs` | ⚠️ | None — `decode_attr_value` reads but never validates flags for known attribute types; see `RFC_AUDIT.md` §4.3 |
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
| Unknown optional transitive attributes preserved in Partial flag | `src/message/` | ✅ | `test_unknown_optional_transitive_preserved` |

**Known gap (found by `RFC_AUDIT.md`, 2026-07-16):** §4.1's "Length field MUST
have the smallest value required... padding of extra data after the message
is not allowed" is enforced for KEEPALIVE (`decode_with_limit` checks
`cur.remaining() != 0`) but not for OPEN or ROUTE_REFRESH — their decoders
stop after reading known/declared-length fields without confirming the
cursor is empty, so trailing padding within the declared header Length is
silently discarded rather than rejected. UPDATE and NOTIFICATION are
unaffected (their trailing fields are defined as "consume the rest of the
message" by the RFC itself, so full consumption is correct there, not
incidental). See `RFC_AUDIT.md` §4.1 for detail; not yet fixed.

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

**Deferred:** `CodecError` variants below the header layer (malformed OPEN/NOTIFICATION
bodies — not RFC 7606-eligible, since that policy is UPDATE-only) are not yet mapped to a
NOTIFICATION; the connection is dropped silently, matching prior behavior. See TODO.md.

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
| Keepalive timer fires at ⌊hold-time / 3⌋ seconds | `src/fsm/mod.rs` | ✅ | `test_keepalive_interval_is_third_of_hold_time` |
| NOTIFICATION sent before session close | `src/fsm/mod.rs` | ✅ | `test_bad_peer_as_sends_notification`, `test_unacceptable_hold_time_sends_notification` |
| Hold time of 0 disables hold timer and keepalive | `src/fsm/mod.rs` | ✅ | `test_hold_time_zero_disables_timers` |
| §8.1 ConnectRetry timer is configurable (`SessionConfig.connect_retry_time`); FSM respects value from transport layer | `src/transport/mod.rs` | ✅ | `DEFAULT_CONNECT_RETRY_TIME` constant; exercised by `gr_phase2_eor_prunes_stale_routes_not_refreshed_by_peer` (2 s config) |

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
| Missing well-known mandatory attribute: **treat-as-withdraw** | `pathvectord/src/daemon/route.rs` | ❌ | **Corrected 2026-07-16 by `RFC_AUDIT.md`.** This row (and the test it cites) previously claimed "session-reset with NOTIFICATION" was the correct, RFC 7606-compliant behavior — it is not. RFC 7606 §3(d) explicitly revises RFC 4271 §6.3 here: "If any of the well-known mandatory attributes are not present in an UPDATE message, then 'treat-as-withdraw' MUST be used." `test_rfc7606_missing_mandatory_resets_session`'s own name asserts the pre-revision behavior while citing RFC 7606 — self-contradictory once checked against the actual RFC 7606 text (fetched and read directly for this audit, not recalled from memory). `pathvectord/src/daemon/route.rs:1011-1049` sends `NotificationMessage`/`MissingWellKnownAttribute` and tears down the entire session when ORIGIN/AS_PATH/(traditional-v4) NEXT_HOP is absent — this is the highest-severity finding of the RFC 7606 audit: any single malformed UPDATE missing a mandatory attribute (an easily-triggered condition — an encoding bug on *any* peer, not an attacker or a narrow race) currently tears down the whole BGP session instead of just withdrawing that one route, which is precisely the class of over-reaction RFC 7606 was written to eliminate. See `RFC_AUDIT.md`'s RFC 7606 section. |

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
| NOTIFICATION error code 2 subcode 7 (Unsupported Capability) on mismatch | `src/message/` | ✅ | `test_unsupported_capability_notification` |
| Retry without capabilities (when peer sends Unsupported Capability NOTIFICATION) | `src/fsm/mod.rs` | ❌ | — |

**Deferred:** Retry-without-capabilities path: when the peer sends NOTIFICATION error 2/7,
we should reconnect advertising no optional parameters. Not yet implemented.

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
`my_as` field when the local ASN exceeds 65535.  
**Boundary:** `Asn` type and `AS_TRANS` constant live in `pathvector-types`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc6793

| Requirement | File | Status | Verified by |
|---|---|---|---|
| FourByteAsn capability (code 65) advertised in OPEN | `src/message/` | ✅ | `test_capability_four_byte_asn_in_open`, interop:gobgp |
| When local ASN > 65535, 2-byte `my_as` field set to AS_TRANS (23456) | `src/message/` | ✅ | `test_open_my_as_uses_as_trans_for_4byte_asn` |
| Four-byte ASN read from NEW_AS4_PATH when peer did not send FourByteAsn cap | `src/message/` | ⚠️ | `test_new_as4_path_fallback` |

**Deferred:** Full NEW_AS4_PATH fallback path (when negotiating with a 2-byte-only peer)
is partially tested but the segment merging logic per RFC 6793 §4.2.3 is not complete.

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
| `TCP_MD5SIG` socket option on outbound socket before `connect()` | `transport/mod.rs` `tcp_connect` | ✅ | — |
| `TCP_MD5SIG` socket option on BGP listener socket per configured peer | `daemon.rs` `run_bgp_listener` | ✅ | — |
| `md5_password` TOML field wired into `SessionConfig` and propagated | `config.rs`, `daemon.rs` | ✅ | `test_md5_password_explicit` |

**Platform note:** Linux only. `apply_tcp_md5sig` is a no-op with a `warn!` log on
non-Linux platforms (macOS dev environment). Key rotation and per-AFI MD5 for IPv6
peers are not yet supported.

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

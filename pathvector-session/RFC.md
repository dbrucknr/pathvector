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
| Attribute flags: Optional, Transitive, Partial, Extended-Length | `src/message/` | ✅ | `test_attribute_flags_roundtrip`, `test_extended_length_attribute` |
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
| Keepalive timer fires at ⌊hold-time / 3⌋ seconds | `src/fsm/mod.rs` | ✅ | `test_keepalive_interval_is_third_of_hold_time` |
| NOTIFICATION sent before session close | `src/fsm/mod.rs` | ✅ | `test_bad_peer_as_sends_notification`, `test_unacceptable_hold_time_sends_notification` |
| Hold time of 0 disables hold timer and keepalive | `src/fsm/mod.rs` | ✅ | `test_hold_time_zero_disables_timers` |

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
| Unknown mandatory attribute: session-reset with NOTIFICATION | `src/message/` | ✅ | `test_rfc7606_missing_mandatory_resets_session` |

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
| Stale timer: retain routes for restart-time seconds during restart | `src/fsm/mod.rs` | ❌ | — |
| EOR (End-of-RIB) marker: empty UPDATE sent after RIB dump | `src/message/` | ❌ | — |

**Deferred:** FSM restart behavior (detecting peer restart, activating stale timer, sending
EOR) requires coordination with `pathvector-rib` and is deferred.

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

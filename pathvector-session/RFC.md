# RFC Requirements — pathvector-session

This crate owns the **wire protocol layer**: message codec, framing, BGP FSM, and
transport. It reads bytes off the wire and produces structured events; it writes
structured messages back to bytes. It has no routing logic and no RIB state.

**Status key:** ✅ Implemented and tested | ⚠️ Partial — see notes | ❌ Not started  
**Verified by key:** `test_name` — unit test | `proptest` — property test | `interop:x` — GoBGP interop | `—` — no automated verification

---

## RFC 4271 §4 — Message Formats

**Owns:** Encode and decode for all four BGP message types: OPEN, UPDATE, NOTIFICATION, KEEPALIVE, plus the common 19-byte header (16-byte marker, 2-byte length, 1-byte type).  
**Boundary:** Path attribute semantics (what the values mean) live in `pathvector-types`.
Decision-making on received routes lives in `pathvector-rib`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4271#section-4

| Requirement | File | Status | Verified by |
|---|---|---|---|
| 19-byte header: 16-byte all-ones marker, 2-byte length, 1-byte type | `src/codec.rs` | ✅ | `test_header_roundtrip`, `test_header_bad_marker` |
| OPEN message encode/decode: version, my-as, hold-time, bgp-id, optional-params | `src/codec.rs` | ✅ | `test_open_roundtrip`, `test_open_invalid_version`, interop:gobgp |
| UPDATE message encode/decode: withdrawn-routes, path-attributes, NLRI | `src/codec.rs` | ✅ | `test_update_roundtrip`, `test_update_empty`, interop:gobgp |
| NOTIFICATION message encode/decode: error-code, error-subcode, data | `src/codec.rs` | ✅ | `test_notification_roundtrip`, `test_notification_cease` |
| KEEPALIVE message encode/decode (header only, no body) | `src/codec.rs` | ✅ | `test_keepalive_roundtrip` |
| Attribute flags: Optional, Transitive, Partial, Extended-Length | `src/codec.rs` | ✅ | `test_attribute_flags_roundtrip`, `test_extended_length_attribute` |
| ORIGIN (type 1) encode/decode | `src/codec.rs` | ✅ | `test_attr_origin_roundtrip` |
| AS_PATH (type 2) encode/decode with AS_SEQUENCE and AS_SET segments | `src/codec.rs` | ✅ | `test_attr_aspath_roundtrip`, `test_attr_aspath_with_set` |
| NEXT_HOP (type 3) encode/decode | `src/codec.rs` | ✅ | `test_attr_next_hop_roundtrip` |
| MULTI_EXIT_DISC (type 4) encode/decode | `src/codec.rs` | ✅ | `test_attr_med_roundtrip` |
| LOCAL_PREF (type 5) encode/decode | `src/codec.rs` | ✅ | `test_attr_local_pref_roundtrip` |
| ATOMIC_AGGREGATE (type 6) encode/decode | `src/codec.rs` | ✅ | `test_attr_atomic_aggregate_roundtrip` |
| AGGREGATOR (type 7) encode/decode | `src/codec.rs` | ✅ | `test_attr_aggregator_roundtrip` |
| COMMUNITY (type 8) encode/decode — RFC 1997 | `src/codec.rs` | ✅ | `test_attr_community_roundtrip` |
| EXTENDED_COMMUNITIES (type 16) encode/decode — RFC 4360 | `src/codec.rs` | ✅ | `test_attr_extended_community_roundtrip` |
| LARGE_COMMUNITY (type 32) encode/decode — RFC 8092 | `src/codec.rs` | ✅ | `test_attr_large_community_roundtrip` |
| Unknown optional transitive attributes preserved in Partial flag | `src/codec.rs` | ✅ | `test_unknown_optional_transitive_preserved` |

---

## RFC 4271 §8 — BGP Finite State Machine

**Owns:** The full 6-state FSM (Idle → Connect → Active → OpenSent → OpenConfirm → Established), timer logic (ConnectRetry, Hold, Keepalive), and event dispatch.  
**Boundary:** Connection collision coordination (choosing which session to drop when two
peers simultaneously open) involves `pathvectord` as the authority on which session to
keep.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4271#section-8

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Idle → Connect on Start event | `src/session.rs` | ✅ | `test_fsm_start_transitions_to_connect` |
| Connect → OpenSent on TCP connection established | `src/session.rs` | ✅ | interop:gobgp |
| Connect → Active on ConnectRetry expiry | `src/session.rs` | ✅ | `test_fsm_connect_retry_timeout` |
| OpenSent → OpenConfirm on valid OPEN received | `src/session.rs` | ✅ | interop:gobgp |
| OpenConfirm → Established on KEEPALIVE received | `src/session.rs` | ✅ | interop:gobgp |
| Any state → Idle on Hold Timer expiry | `src/session.rs` | ✅ | `test_fsm_hold_timer_expiry` |
| Keepalive timer fires at ⌊hold-time / 3⌋ seconds | `src/session.rs` | ✅ | `test_keepalive_interval_derivation` |
| NOTIFICATION sent before session close | `src/session.rs` | ✅ | `test_fsm_sends_notification_on_error` |
| Hold time of 0 disables hold timer and keepalive | `src/session.rs` | ✅ | `test_hold_time_zero_disables_timers` |

---

## RFC 7606 — Revised Error Handling for BGP UPDATE Messages

**Owns:** Per-attribute error handling policy: when to treat-as-withdraw, when to discard
the attribute, when to reset the session.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc7606

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Malformed ORIGIN: treat-as-withdraw | `src/codec.rs` | ✅ | `test_rfc7606_malformed_origin_treat_as_withdraw` |
| Malformed AS_PATH: treat-as-withdraw | `src/codec.rs` | ✅ | `test_rfc7606_malformed_aspath_treat_as_withdraw` |
| Malformed NEXT_HOP: treat-as-withdraw | `src/codec.rs` | ✅ | `test_rfc7606_malformed_next_hop_treat_as_withdraw` |
| Malformed LOCAL_PREF: treat-as-withdraw | `src/codec.rs` | ✅ | `test_rfc7606_malformed_local_pref_treat_as_withdraw` |
| Unknown optional non-transitive attribute: attribute-discard | `src/codec.rs` | ✅ | `test_rfc7606_unknown_optional_nontransitive_discarded` |
| Unknown mandatory attribute: session-reset with NOTIFICATION | `src/codec.rs` | ✅ | `test_rfc7606_missing_mandatory_resets_session` |

---

## RFC 2918 — Route Refresh Capability for BGP-4

**Owns:** ROUTE-REFRESH message codec and capability advertisement.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc2918

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Capability code 2 advertised in OPEN | `src/codec.rs` | ✅ | `test_capability_route_refresh_in_open` |
| ROUTE-REFRESH message (type 5) encode/decode with AFI + reserved + SAFI | `src/codec.rs` | ✅ | `test_route_refresh_roundtrip` |

---

## RFC 5492 — Capabilities Advertisement with BGP-4

**Owns:** Optional parameter TLV encoding (type 2 = Capability) in OPEN; parsing capability
list; NOTIFICATION for unsupported capabilities.  
**Boundary:** Individual capability semantics owned by the RFC that defines them.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc5492

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Optional parameter type 2 TLV parsed as capability list | `src/codec.rs` | ✅ | `test_capability_tlv_roundtrip` |
| NOTIFICATION error code 2 subcode 7 (Unsupported Capability) on mismatch | `src/codec.rs` | ✅ | `test_unsupported_capability_notification` |
| Retry without capabilities (when peer sends Unsupported Capability NOTIFICATION) | `src/session.rs` | ❌ | — |

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
| MP_REACH_NLRI (type 14): AFI, SAFI, next-hop length, next-hop, SNPA, NLRI | `src/codec.rs` | ✅ | `test_mp_reach_ipv6_roundtrip`, interop:gobgp |
| MP_UNREACH_NLRI (type 15): AFI, SAFI, withdrawn NLRI | `src/codec.rs` | ✅ | `test_mp_unreach_ipv6_roundtrip` |
| IPv6 global unicast next-hop (16-byte form) | `src/codec.rs` | ✅ | `test_mp_reach_ipv6_roundtrip` |
| IPv6 link-local next-hop (32-byte form: global + link-local) | `src/codec.rs` | ✅ | `test_mp_reach_ipv6_link_local_roundtrip` |

---

## RFC 6793 — Four-Octet AS Number Capability

**Owns:** FourByteAsn capability (code 65) negotiation; AS_TRANS substitution in the 2-byte
`my_as` field when the local ASN exceeds 65535.  
**Boundary:** `Asn` type and `AS_TRANS` constant live in `pathvector-types`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc6793

| Requirement | File | Status | Verified by |
|---|---|---|---|
| FourByteAsn capability (code 65) advertised in OPEN | `src/codec.rs` | ✅ | `test_capability_four_byte_asn_in_open`, interop:gobgp |
| When local ASN > 65535, 2-byte `my_as` field set to AS_TRANS (23456) | `src/codec.rs` | ✅ | `test_open_my_as_uses_as_trans_for_4byte_asn` |
| Four-byte ASN read from NEW_AS4_PATH when peer did not send FourByteAsn cap | `src/codec.rs` | ⚠️ | `test_new_as4_path_fallback` |

**Deferred:** Full NEW_AS4_PATH fallback path (when negotiating with a 2-byte-only peer)
is partially tested but the segment merging logic per RFC 6793 §4.2.3 is not complete.

---

## RFC 6286 — Autonomous-System-Wide Unique BGP Identifier

**Owns:** Rejection of duplicate BGP ID from iBGP peers in `validate_open`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc6286

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Duplicate iBGP BGP-ID rejected with NOTIFICATION (OPEN error, Bad BGP Identifier) | `src/session.rs` | ✅ | `test_duplicate_bgp_id_rejected`, interop:gobgp |

---

## RFC 4724 — Graceful Restart Mechanism for BGP

**Owns:** Graceful Restart capability (code 64) parsing and forwarding via `SessionInfo`.
The FSM restart behavior is deferred.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4724

| Requirement | File | Status | Verified by |
|---|---|---|---|
| GracefulRestart capability (code 64) parsed from OPEN | `src/codec.rs` | ✅ | `test_capability_graceful_restart_parsed` |
| Capability forwarded to `SessionInfo` for upper layers | `src/session.rs` | ✅ | `test_session_info_carries_graceful_restart` |
| Stale timer: retain routes for restart-time seconds during restart | `src/session.rs` | ❌ | — |
| EOR (End-of-RIB) marker: empty UPDATE sent after RIB dump | `src/codec.rs` | ❌ | — |

**Deferred:** FSM restart behavior (detecting peer restart, activating stale timer, sending
EOR) requires coordination with `pathvector-rib` and is deferred.

---

## RFC 4486 — Subcodes for BGP Cease NOTIFICATION Message

**Owns:** All 10 Cease NOTIFICATION subcodes as named constants and enum variants.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4486

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Subcode 1: Maximum Number of Prefixes Reached | `src/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |
| Subcode 2: Administrative Shutdown | `src/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |
| Subcode 3: Peer De-configured | `src/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |
| Subcode 4: Administrative Reset | `src/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |
| Subcode 5: Connection Rejected | `src/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |
| Subcode 6: Other Configuration Change | `src/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |
| Subcode 7: Connection Collision Resolution | `src/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |
| Subcode 8: Out of Resources | `src/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |
| Subcode 9: Hard Reset | `src/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |
| Subcode 10: BFD Down | `src/notification.rs` | ✅ | `test_cease_subcodes_all_defined` |

---

## RFC 6608 — Subcodes for BGP Finite State Machine Error

**Owns:** FSM error subcodes 0 (Unspecified), 1 (Unexpected message in OpenSent),
2 (Unexpected message in OpenConfirm), 3 (Unexpected message in Established).  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc6608

| Requirement | File | Status | Verified by |
|---|---|---|---|
| FSM error subcode 0: Unspecified Error | `src/notification.rs` | ✅ | `test_fsm_error_subcodes_all_defined` |
| FSM error subcode 1: Receive Unexpected Message in OpenSent State | `src/notification.rs` | ✅ | `test_fsm_error_subcodes_all_defined` |
| FSM error subcode 2: Receive Unexpected Message in OpenConfirm State | `src/notification.rs` | ✅ | `test_fsm_error_subcodes_all_defined` |
| FSM error subcode 3: Receive Unexpected Message in Established State | `src/notification.rs` | ✅ | `test_fsm_error_subcodes_all_defined` |

---

## RFC 8654 — Extended Message Support for BGP

**Owns:** ExtendedMessage capability (code 6); raising the message size limit from 4096 to
65535 bytes when both peers negotiate the capability.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc8654

| Requirement | File | Status | Verified by |
|---|---|---|---|
| ExtendedMessage capability (code 6) decoded from OPEN | `src/codec.rs` | ✅ | `test_capability_extended_message_parsed` |
| Message size limit raised to 65535 when both peers advertise capability | `src/codec.rs` | ✅ | `test_extended_message_limit_applies_when_negotiated`, interop:gobgp |
| Message size limit stays at 4096 when capability not negotiated | `src/codec.rs` | ✅ | `test_message_limit_4096_without_extended_message_cap` |

---

## RFC 2385 — Protection of BGP Sessions via MD5 (Deferred)

**Datatracker:** https://datatracker.ietf.org/doc/html/rfc2385

| Requirement | File | Status | Verified by |
|---|---|---|---|
| TCP MD5 socket option set on listener and outbound sockets when configured | — | ❌ | — |

**Deferred:** Requires OS-level socket option (`TCP_MD5SIG`). Platform support and key
management are deferred.

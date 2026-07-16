# RFC Requirements — pathvector-types

This crate owns the **type-system layer**: BGP wire types, named constants, and encoding
primitives. It has no protocol logic, no session state, and no RIB. Every other crate in
the workspace depends on it; it depends on nothing within the workspace.

**Status key:** ✅ Implemented and tested | ⚠️ Partial — see notes | ❌ Not started  
**Verified by key:** `test_name` — unit test | `proptest` — property test | `—` — no automated verification

---

## RFC 4271 §5 — Path Attribute Types

**Owns:** The Rust structs for each well-known and optional BGP path attribute. Semantic
invariants (e.g. ordering, default values) are enforced here.  
**Boundary:** Wire encoding/decoding lives in `pathvector-session`. Best-path comparison
logic that uses these types lives in `pathvector-rib`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4271#section-5

| Requirement | File | Status | Verified by |
|---|---|---|---|
| ORIGIN (type 1): IGP=0, EGP=1, INCOMPLETE=2 | `src/attr.rs` | ✅ | `test_origin_values`, `test_origin_from_u8`, `test_origin_ordering` |
| AS_PATH (type 2): AS_SET and AS_SEQUENCE segments; path length | `src/aspath.rs` | ✅ | `test_aspath_from_sequence`, `test_aspath_display_mixed`, `test_as_path_with_set_roundtrip` |
| AS_PATH prepend inserts own ASN at front of first AS_SEQUENCE | `src/aspath.rs` | ✅ | `test_aspath_prepend_to_sequence` |
| AS_PATH prepend creates new AS_SEQUENCE when first segment is AS_SET | `src/aspath.rs` | ✅ | `test_aspath_prepend_to_set_creates_new_segment` |
| AS_PATH prepend creates new AS_SEQUENCE when existing sequence is full (255 entries) | `src/aspath.rs` | ✅ | `test_aspath_prepend_overflow_creates_new_segment` |
| NEXT_HOP (type 3): IPv4 and IPv6 variants | `src/attr.rs` | ✅ | `test_next_hop_v4`, `test_next_hop_too_short_is_error` |
| MULTI_EXIT_DISC / MED (type 4): optional non-transitive u32 | `src/attr.rs` | ✅ | `test_med_ordering`, `test_med_too_short_is_error` |
| LOCAL_PREF (type 5): iBGP only; default 100 when absent | `src/attr.rs` | ✅ | `test_local_pref_ordering`, `test_local_pref_default`, `test_local_pref_too_short_is_error` |
| ATOMIC_AGGREGATE (type 6): flag-only attribute | `src/attr.rs` | ✅ | `test_atomic_aggregate_display`, `test_atomic_aggregate_and_aggregator_roundtrip` |
| AGGREGATOR (type 7): optional transitive ASN + IPv4 router-id | `src/attr.rs` | ✅ | `test_aggregator_new`, `test_aggregator_display`, `test_aggregator_too_short_is_error` |

---

## RFC 6793 — BGP Support for Four-Octet AS Numbers

**Owns:** The `Asn` type as a 32-bit value; the `AS_TRANS` constant.  
**Boundary:** FourByteAsn capability negotiation and AS_TRANS substitution in the `my_as`
field live in `pathvector-session`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc6793

| Requirement | File | Status | Verified by |
|---|---|---|---|
| `Asn` stored as 32-bit value | `src/asn.rs` | ✅ | `test_asn_new_and_value`, `test_asn_is_four_byte` |
| `AS_TRANS` (23456) is a named constant | `src/asn.rs` | ✅ | `test_asn_is_trans` |

---

## RFC 1930 — AS Number Guidelines (Private Range, 2-Byte)

**Owns:** Recognition of the 2-byte private ASN range.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc1930

| Requirement | File | Status | Verified by |
|---|---|---|---|
| 2-byte private ASN range 64512–65534 recognised by `is_private()` | `src/asn.rs` | ✅ | `test_asn_is_private` |

---

## RFC 6996 — AS Reservation for Private Use (4-Byte Range)

**Owns:** Recognition of the 4-byte private ASN range.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc6996

| Requirement | File | Status | Verified by |
|---|---|---|---|
| 4-byte private ASN range 4200000000–4294967294 recognised by `is_private()` | `src/asn.rs` | ✅ | `test_asn_is_private` |

---

## RFC 5065 — AS Confederations for BGP

**Owns:** Confederation segment types and the `strip_confed_segments()` helper.  
**Boundary:** Confederation segment stripping before eBGP advertisement is applied in
`pathvector-rib` (`AdjRibOut`). Best-path step 4 (confederation segments count as 0)
is enforced in `pathvector-rib`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc5065

| Requirement | File | Status | Verified by |
|---|---|---|---|
| AS_CONFED_SEQUENCE (segment type 3) and AS_CONFED_SET (segment type 4) defined | `src/aspath.rs` | ✅ | `test_segment_display_confed_sequence`, `test_segment_display_confed_set`, `test_as_path_confed_segments_roundtrip` |
| `AsPath::strip_confed_segments()` removes all confederation segments | `src/aspath.rs` | ✅ | `test_strip_confed_segments_removes_confed_sequence_and_set`, `test_strip_confed_segments_preserves_sequence_and_set`, `test_strip_confed_segments_all_confed_yields_empty`, `test_strip_confed_segments_empty_path_stays_empty`, `test_strip_confed_segments_does_not_mutate_original`, `test_strip_confed_segments_preserves_segment_order` |

---

## RFC 1997 — BGP Communities Attribute

**Owns:** The `Community` type, well-known community constants, and the `is_well_known()` predicate.  
**Boundary:** Wire encoding in `pathvector-session`. Policy match/action logic in `pathvector-policy`. BLACKHOLE constant details in RFC 7999 section below.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc1997

| Requirement | File | Status | Verified by |
|---|---|---|---|
| COMMUNITY (type 8): 32-bit value written as `high:low` | `src/community.rs` | ✅ | `test_community_new`, `test_community_from_parts_roundtrip`, `test_community_display` |
| Well-known community NO_EXPORT (0xFFFFFF01) — value + `is_no_export()` predicate | `src/community.rs` | ✅ | `test_community_well_known_no_export` |
| Well-known community NO_ADVERTISE (0xFFFFFF02) — value + `is_no_advertise()` predicate | `src/community.rs` | ✅ | `test_community_well_known_no_advertise` |
| Well-known community NO_EXPORT_SUBCONFED (0xFFFFFF03) — value + predicate | `src/community.rs` | ✅ | `test_community_well_known_no_export_subconfed` |
| Operator-assigned values do not collide with well-known range | `src/community.rs` | ✅ | `test_community_operator_not_well_known` |
| **RFC 1997's mandated behavior** for these three values — "MUST NOT be advertised outside a BGP confederation boundary" (NO_EXPORT), "MUST NOT be advertised to other BGP peers" (NO_ADVERTISE), "MUST NOT be advertised to external BGP peers" (NO_EXPORT_SUBCONFED) | — | ❌ | Added 2026-07-16 by `RFC_AUDIT.md`. The predicates above exist and are correctly tested at the type level, but grepping `pathvectord/src/outbound.rs` and `pathvector-rib` for any call to `is_no_export()`/`is_no_advertise()`/`is_well_known()` in the actual propagation path turns up nothing — they're never used to gate whether a route is advertised. A route tagged with any of these three values propagates completely normally today. This is the same "wire format defined, behavior not wired up" pattern as the SAFI-constant RFCs below, but unlike those, this one wasn't previously flagged as such. |

**Known gap (found 2026-07-16 by `RFC_AUDIT.md`):** see the row above — this
crate correctly defines and can detect the three well-known community
values, but nothing downstream currently enforces the RFC-mandated
propagation restriction they carry.

---

## RFC 4360 — BGP Extended Communities Attribute

**Owns:** The `ExtendedCommunity` type (8-byte typed value), type byte layout, and Route
Target / Route Origin subtype constructors.  
**Boundary:** Wire encoding in `pathvector-session`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4360

| Requirement | File | Status | Verified by |
|---|---|---|---|
| EXTENDED_COMMUNITIES (type 16): list of 8-byte typed communities | `src/community.rs` | ✅ | `test_extended_community_bytes_roundtrip`, `test_extended_community_display` |
| Type byte encodes IANA authority (high bit) and transitivity (bit 6) | `src/community.rs` | ✅ | `test_extended_community_non_transitive` |
| Route Target subtype (type 0x00/0x01/0x02, subtype 0x02) byte layout | `src/community.rs` | ✅ | `test_extended_community_route_target_as2`, `test_extended_community_route_target_as4` |
| Route Origin subtype byte layout | `src/community.rs` | ✅ | `test_extended_community_route_origin_as2` |

---

## RFC 8092 — BGP Large Communities Attribute

**Owns:** The `LargeCommunity` type (12-byte value: global-admin:local-data-1:local-data-2).  
**Boundary:** Wire encoding in `pathvector-session`. Policy match/action in `pathvector-policy`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc8092

| Requirement | File | Status | Verified by |
|---|---|---|---|
| LARGE_COMMUNITY (type 32): 12-byte value, `global:local1:local2` display | `src/community.rs` | ✅ | `test_large_community_new`, `test_large_community_bytes_roundtrip`, `test_large_community_display` |

---

## RFC 7999 — BLACKHOLE Community

**Owns:** The `BLACKHOLE` constant (0xFFFF029A) and the `is_blackhole()` predicate.  
**Boundary:** The discard action on BLACKHOLE routes is wired in `pathvectord`. The policy
integration point (using `is_blackhole()` as a condition) is in `pathvector-policy`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc7999

| Requirement | File | Status | Verified by |
|---|---|---|---|
| BLACKHOLE community value 0xFFFF029A defined as a named constant | `src/community.rs` | ✅ | `test_community_blackhole` |
| `is_blackhole()` returns true only for 0xFFFF029A | `src/community.rs` | ✅ | `test_community_blackhole` |

---

## RFC 4760 — Multiprotocol Extensions for BGP-4 (AFI/SAFI Registry)

**Owns:** The `Afi`, `Safi`, and `AfiSafi` constant registry; the IPv6 `NextHop` variant
including the link-local address form.  
**Boundary:** MP_REACH_NLRI / MP_UNREACH_NLRI wire encoding lives in `pathvector-session`.
Daemon processing of multiprotocol routes lives in `pathvectord`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4760

| Requirement | File | Status | Verified by |
|---|---|---|---|
| AFI and SAFI type registry (IPv4, IPv6, L2VPN, and well-known SAFIs) | `src/afi.rs` | ✅ | `test_afi_constants`, `test_safi_constants`, `test_afisafi_constants` |
| IPv6 next-hop may carry both global unicast and link-local addresses | `src/attr.rs` | ✅ | `test_next_hop_v6_with_link_local`, `test_mp_reach_ipv6_link_local_roundtrip` |

---

## RFC 3107, RFC 4364, RFC 4761, RFC 7432, RFC 5575 — SAFI Constants (Encoding Deferred)

**Owns:** SAFI constant definitions for MPLS, VPN, VPLS, EVPN, and FlowSpec address families.  
**Boundary:** NLRI encoding for these address families is deferred to `pathvector-session`.  
**Datatracker:** RFC 3107: https://datatracker.ietf.org/doc/html/rfc3107 | RFC 4364: https://datatracker.ietf.org/doc/html/rfc4364

| Requirement | File | Status | Verified by |
|---|---|---|---|
| `Safi::MPLS_LABELED` (value 4) — RFC 3107 | `src/afi.rs` | ✅ | `test_safi_constants` |
| `Safi::MPLS_VPN` (value 128) — RFC 4364 | `src/afi.rs` | ✅ | `test_safi_constants` |
| `Safi::VPLS` (value 65) and `Afi::L2VPN` (25) — RFC 4761 | `src/afi.rs` | ✅ | `test_safi_constants`, `test_afi_constants` |
| `Safi::EVPN` (value 70) and `Afi::L2VPN` (25) — RFC 7432 | `src/afi.rs` | ✅ | `test_safi_constants`, `test_afi_constants` |
| `Safi::FLOW_SPEC` (value 133) — RFC 5575 | `src/afi.rs` | ✅ | `test_safi_constants` |

**Deferred:** Route Distinguisher type (RFC 4364) — struct and parsing not yet defined.
MPLS label stack, VPN-IPv4, VPLS, EVPN route type, and FlowSpec component encoding all
deferred to `pathvector-session` when those address families are implemented.

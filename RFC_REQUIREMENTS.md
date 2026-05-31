# BGP RFC Requirements

Tracks every RFC that pathvector sets out to implement, the concrete
requirements it imposes, which module owns each requirement, and the current
implementation status.

**Status key**
- ✅ Implemented and tested
- ⚠️ Partial — see notes
- ❌ Not started

---

## RFC 4271 — A Border Gateway Protocol 4 (BGP-4)

The core protocol. Every crate is shaped by it.

### §4 — Message Formats

| Requirement | Module | Status |
|---|---|---|
| 16-byte all-ones marker in every message header | `pathvector-session/src/message/header.rs` | ✅ |
| 2-byte length field (min 19, max 4096) | `pathvector-session/src/message/header.rs` | ✅ |
| 1-byte type field (OPEN=1, UPDATE=2, NOTIFICATION=3, KEEPALIVE=4) | `pathvector-session/src/message/header.rs` | ✅ |
| OPEN: version=4, my_as, hold_time, bgp_id, optional parameters | `pathvector-session/src/message/open.rs` | ✅ |
| OPEN: reject hold_time values of 1 or 2 (must be 0 or ≥ 3) | `pathvector-session/src/fsm/mod.rs` | ✅ |
| UPDATE: withdrawn NLRI length + withdrawn NLRIs | `pathvector-session/src/message/update.rs` | ✅ |
| UPDATE: total path attribute length + path attributes | `pathvector-session/src/message/update.rs` | ✅ |
| UPDATE: NLRI (announced prefixes) | `pathvector-session/src/message/update.rs` | ✅ |
| NLRI variable-length prefix encoding (only significant bytes on wire) | `pathvector-session/src/message/update.rs` | ✅ |
| NOTIFICATION: error code + subcode + optional data | `pathvector-session/src/message/notification.rs` | ✅ |
| NOTIFICATION error code 1 — Message Header Error (subcodes 1–3) | `pathvector-session/src/message/notification.rs` | ✅ |
| NOTIFICATION error code 2 — OPEN Message Error (subcodes 1–7) | `pathvector-session/src/message/notification.rs` | ✅ |
| NOTIFICATION error code 3 — UPDATE Message Error (subcodes 1–11) | `pathvector-session/src/message/notification.rs` | ✅ |
| NOTIFICATION error code 4 — Hold Timer Expired | `pathvector-session/src/message/notification.rs` | ✅ |
| NOTIFICATION error code 5 — Finite State Machine Error | `pathvector-session/src/message/notification.rs` | ✅ |
| KEEPALIVE: header only, no body | `pathvector-session/src/message/mod.rs` | ✅ |

### §5 — Path Attributes

| Requirement | Module | Status |
|---|---|---|
| ORIGIN (type 1, well-known mandatory): IGP=0, EGP=1, INCOMPLETE=2 | `pathvector-types/src/attr.rs` | ✅ |
| AS_PATH (type 2, well-known mandatory): AS_SET(1) and AS_SEQUENCE(2) segments | `pathvector-types/src/aspath.rs` | ✅ |
| AS_PATH prepend inserts own ASN at front of first AS_SEQUENCE | `pathvector-types/src/aspath.rs` | ✅ |
| AS_PATH prepend creates new AS_SEQUENCE when first segment is AS_SET | `pathvector-types/src/aspath.rs` | ✅ |
| AS_PATH prepend creates new AS_SEQUENCE when existing sequence is full (255 entries) | `pathvector-types/src/aspath.rs` | ✅ |
| NEXT_HOP (type 3, well-known mandatory for IPv4 unicast) | `pathvector-types/src/attr.rs` | ✅ |
| MULTI_EXIT_DISC / MED (type 4, optional non-transitive) | `pathvector-types/src/attr.rs` | ✅ |
| LOCAL_PREF (type 5, well-known discretionary, iBGP only) | `pathvector-types/src/attr.rs` | ✅ |
| ATOMIC_AGGREGATE (type 6, well-known discretionary, flag only) | `pathvector-types/src/attr.rs` | ✅ |
| AGGREGATOR (type 7, optional transitive): ASN + IPv4 router-id | `pathvector-types/src/attr.rs` | ✅ |
| Path attribute flag bits: Optional, Transitive, Partial, Extended Length | `pathvector-session/src/message/update.rs` | ✅ |
| Unknown transitive attributes preserved (Partial bit set, forwarded) | `pathvector-session/src/message/update.rs` | ⚠️ Preserved as `Unknown` variant; Partial bit not actively set on re-encode |

### §8 — Finite State Machine

| Requirement | Module | Status |
|---|---|---|
| States: Idle, Connect, Active, OpenSent, OpenConfirm, Established | `pathvector-session/src/fsm/mod.rs` | ✅ |
| Events: ManualStart, ManualStop, ConnectRetryTimerExpired, HoldTimerExpired, KeepaliveTimerExpired, TcpConnected, TcpFailed, MessageReceived | `pathvector-session/src/fsm/mod.rs` | ✅ |
| Connect-retry timer (default 120 s) | `pathvector-session/src/fsm/mod.rs` | ✅ |
| Hold timer negotiated as min(local, peer); send KEEPALIVE at 1/3 of hold time | `pathvector-session/src/fsm/mod.rs` | ✅ |
| Open hold timer (240 s) while waiting for peer OPEN | `pathvector-session/src/fsm/mod.rs` | ✅ |
| Send NOTIFICATION and close TCP on any error | `pathvector-session/src/fsm/mod.rs` | ✅ |
| Connection collision detection (higher BGP ID keeps outbound connection) | `pathvector-session/src/fsm/mod.rs` | ❌ BGP ID field exists but collision logic not implemented |

### §9 — Decision Process (Best-Path Selection)

| Requirement | Module | Status |
|---|---|---|
| Step 1: Prefer routes with reachable next-hop | `pathvector-rib/src/best_path.rs` | ❌ Requires IGP integration |
| Step 2: Prefer highest LOCAL_PREF (missing → 100) | `pathvector-rib/src/best_path.rs` | ✅ |
| Step 3: Prefer locally originated routes | `pathvector-rib/src/best_path.rs` | ❌ Requires session-type tag from session layer |
| Step 4: Prefer shortest AS_PATH (AS_SET counts as 1, AS_CONFED_* count as 0) | `pathvector-rib/src/best_path.rs` | ✅ |
| Step 5: Prefer lowest ORIGIN (IGP < EGP < INCOMPLETE) | `pathvector-rib/src/best_path.rs` | ✅ |
| Step 6: Prefer lowest MED (missing → 0; same-AS comparison only) | `pathvector-rib/src/best_path.rs` | ✅ |
| Step 7: Prefer eBGP over iBGP | `pathvector-rib/src/best_path.rs` | ❌ Requires session-type tag |
| Step 8: Prefer lowest IGP metric to next-hop | `pathvector-rib/src/best_path.rs` | ❌ Requires IGP integration |
| Step 9: Prefer oldest eBGP route | `pathvector-rib/src/best_path.rs` | ❌ Requires route-age tracking |
| Step 10: Prefer lowest peer IP address (tiebreaker) | `pathvector-rib/src/best_path.rs` | ✅ |

### §9.2 — RIB Structure

| Requirement | Module | Status |
|---|---|---|
| Adj-RIB-In: per-peer store of received routes before policy | `pathvector-rib/src/adj_rib_in.rs` | ✅ |
| Loc-RIB: post-policy best routes selected for use | `pathvector-rib/src/loc_rib.rs` | ✅ |
| Adj-RIB-Out: per-peer store of routes to be advertised | `pathvector-rib/src/adj_rib_out.rs` | ✅ |
| iBGP split horizon: do not re-advertise routes learned from iBGP to other iBGP peers | `pathvector-rib/src/adj_rib_out.rs` | ⚠️ AdjRibOut exists but iBGP/eBGP distinction not yet enforced |

---

## RFC 2918 — Route Refresh Capability

| Requirement | Module | Status |
|---|---|---|
| RouteRefresh capability (code 2) advertised in OPEN | `pathvector-session/src/message/open.rs` | ✅ |
| ROUTE-REFRESH message (type 5): AFI (2 bytes) + reserved (1 byte) + SAFI (1 byte) | `pathvector-session/src/message/route_refresh.rs` | ✅ |
| ROUTE-REFRESH only sent/honoured when both peers have negotiated the capability | `pathvector-session/src/fsm/mod.rs` | ⚠️ Capability is parsed; enforcement of the negotiation guard is the session layer's responsibility |

---

## RFC 3392 — Capabilities Advertisement

| Requirement | Module | Status |
|---|---|---|
| Optional parameters encoded as type-length-value in OPEN | `pathvector-session/src/message/open.rs` | ✅ |
| Optional parameter type 2 wraps capability TLVs | `pathvector-session/src/message/open.rs` | ✅ |
| Unknown optional parameter types silently skipped | `pathvector-session/src/message/open.rs` | ✅ |
| Unknown capability codes preserved in `Unknown` variant | `pathvector-session/src/message/open.rs` | ✅ |

---

## RFC 4760 — Multiprotocol Extensions for BGP-4

| Requirement | Module | Status |
|---|---|---|
| MultiProtocol capability (code 1): AFI (2) + reserved (1) + SAFI (1) | `pathvector-session/src/message/open.rs` | ✅ |
| MP_REACH_NLRI (type 14): AFI, SAFI, next-hop length, next-hop, NLRI | `pathvector-session/src/message/update.rs` | ✅ |
| MP_UNREACH_NLRI (type 15): AFI, SAFI, withdrawn NLRI | `pathvector-session/src/message/update.rs` | ✅ |
| IPv6 next-hop may carry both global unicast and link-local addresses | `pathvector-types/src/attr.rs` | ✅ |
| AFI and SAFI type registry (IPv4, IPv6, L2VPN, and well-known SAFIs) | `pathvector-types/src/afi.rs` | ✅ |

---

## RFC 6793 — BGP Support for Four-Octet Autonomous System (AS) Numbers

| Requirement | Module | Status |
|---|---|---|
| Asn stored as 32-bit value | `pathvector-types/src/asn.rs` | ✅ |
| AS_TRANS (23456) substituted in 2-byte `my_as` field when local ASN > 65535 | `pathvector-session/src/fsm/mod.rs` | ✅ |
| FourByteAsn capability (code 65): carries full 32-bit ASN | `pathvector-session/src/message/open.rs` | ✅ |
| AS4_PATH (type 17): 4-byte AS path carried during 2-byte/4-byte transition | `pathvector-session/src/message/update.rs` | ✅ |
| AS4_AGGREGATOR (type 18): 4-byte aggregator during transition | `pathvector-session/src/message/update.rs` | ✅ |
| When both peers support 4-byte ASN, AS_PATH uses 4-byte encoding directly | `pathvector-session/src/fsm/mod.rs` | ✅ |

---

## RFC 4724 — Graceful Restart Mechanism for BGP

| Requirement | Module | Status |
|---|---|---|
| GracefulRestart capability (code 64): restart flags, restart time (max 4095 s), per-family forwarding-preserved flag | `pathvector-session/src/message/open.rs` | ✅ |
| Capability forwarded to caller via `SessionInfo` | `pathvector-session/src/fsm/mod.rs` | ✅ |
| FSM holds forwarding state while control plane restarts | `pathvector-session/src/fsm/mod.rs` | ❌ Not implemented |
| Stale route timer — mark routes stale and withdraw after timer expires | `pathvector-rib` | ❌ Not implemented |

---

## RFC 4486 — Subcodes for BGP Cease NOTIFICATION Message

| Requirement | Module | Status |
|---|---|---|
| Subcode 1 — Maximum Number of Prefixes Reached | `pathvector-session/src/message/notification.rs` | ✅ |
| Subcode 2 — Administrative Shutdown | `pathvector-session/src/message/notification.rs` | ✅ |
| Subcode 3 — Peer Deconfigured | `pathvector-session/src/message/notification.rs` | ✅ |
| Subcode 4 — Administrative Reset | `pathvector-session/src/message/notification.rs` | ✅ |
| Subcode 5 — Connection Rejected | `pathvector-session/src/message/notification.rs` | ✅ |
| Subcode 6 — Other Configuration Change | `pathvector-session/src/message/notification.rs` | ✅ |
| Subcode 7 — Connection Collision Resolution | `pathvector-session/src/message/notification.rs` | ✅ |
| Subcode 8 — Out of Resources | `pathvector-session/src/message/notification.rs` | ✅ |
| Subcode 9 — Hard Reset | `pathvector-session/src/message/notification.rs` | ✅ |
| Subcode 10 — BFD Down | `pathvector-session/src/message/notification.rs` | ✅ |

---

## RFC 1997 — BGP Communities Attribute

| Requirement | Module | Status |
|---|---|---|
| COMMUNITY (type 8): list of 32-bit values, written as high:low | `pathvector-types/src/community.rs` | ✅ |
| Community encoded/decoded in UPDATE path attributes | `pathvector-session/src/message/update.rs` | ✅ |
| Well-known community NO_EXPORT (0xFFFFFF01) | `pathvector-types/src/community.rs` | ✅ |
| Well-known community NO_ADVERTISE (0xFFFFFF02) | `pathvector-types/src/community.rs` | ✅ |
| Well-known community NO_EXPORT_SUBCONFED (0xFFFFFF03) | `pathvector-types/src/community.rs` | ✅ |
| Match on community in policy | `pathvector-policy/src/condition.rs` | ✅ |
| Add community in policy action | `pathvector-policy/src/action.rs` | ✅ |

---

## RFC 4360 — BGP Extended Communities Attribute

| Requirement | Module | Status |
|---|---|---|
| EXTENDED_COMMUNITIES (type 16): list of 8-byte typed communities | `pathvector-types/src/community.rs` | ✅ |
| Type byte encodes IANA authority (high bit) and transitivity (bit 6) | `pathvector-types/src/community.rs` | ✅ |
| Route Target subtype (type 0x00/0x01/0x02, subtype 0x02) | `pathvector-types/src/community.rs` | ✅ |
| Extended communities encoded/decoded in UPDATE | `pathvector-session/src/message/update.rs` | ✅ |

---

## RFC 8092 — BGP Large Communities Attribute

| Requirement | Module | Status |
|---|---|---|
| LARGE_COMMUNITY (type 32): list of 12-byte values (global-admin:local-data-1:local-data-2) | `pathvector-types/src/community.rs` | ✅ |
| Large communities encoded/decoded in UPDATE | `pathvector-session/src/message/update.rs` | ✅ |
| Match on large community in policy | `pathvector-policy/src/condition.rs` | ✅ |
| Add large community in policy action | `pathvector-policy/src/action.rs` | ✅ |

---

## RFC 7999 — BLACKHOLE Community

| Requirement | Module | Status |
|---|---|---|
| BLACKHOLE community value 0xFFFF029A defined | `pathvector-types/src/community.rs` | ✅ |
| `is_blackhole()` predicate | `pathvector-types/src/community.rs` | ✅ |
| Routers receiving BLACKHOLE discard traffic to the prefix | `pathvector-policy` / `pathvectord` | ❌ No discard/null-route action wired up yet |

---

## RFC 1930 — Guidelines for creation, selection, and registration of an AS

| Requirement | Module | Status |
|---|---|---|
| 2-byte private ASN range 64512–65534 | `pathvector-types/src/asn.rs` | ✅ |
| `is_private()` returns true for private ASNs | `pathvector-types/src/asn.rs` | ✅ |

---

## RFC 6996 — Autonomy System (AS) Reservation for Private Use

| Requirement | Module | Status |
|---|---|---|
| 4-byte private ASN range 4200000000–4294967294 | `pathvector-types/src/asn.rs` | ✅ |

---

## RFC 5065 — Autonomous System Confederations for BGP

| Requirement | Module | Status |
|---|---|---|
| AS_CONFED_SEQUENCE (segment type 3) and AS_CONFED_SET (segment type 4) | `pathvector-types/src/aspath.rs` | ✅ |
| Confederation segments count as 0 in AS path length (best-path step 4) | `pathvector-rib/src/best_path.rs` | ✅ |
| Confederation segments stripped before advertising to eBGP peers | `pathvector-rib/src/adj_rib_out.rs` | ❌ Not implemented |

---

## RFC 4456 — BGP Route Reflection

| Requirement | Module | Status |
|---|---|---|
| ORIGINATOR_ID (type 9): router-id of originating route reflector client | `pathvector-types` / `pathvector-rib` | ❌ Attribute type not modeled |
| CLUSTER_LIST (type 10): sequence of cluster IDs the route has passed through | `pathvector-types` / `pathvector-rib` | ❌ Attribute type not modeled |
| Route reflector loop prevention using ORIGINATOR_ID and CLUSTER_LIST | `pathvector-rib` | ❌ Not implemented |
| Route reflector client/non-client peer classification | `pathvector-session` / `pathvector-rib` | ❌ Not implemented |

---

## RFC 3107 — Carrying Label Information in BGP-4

| Requirement | Module | Status |
|---|---|---|
| Safi::MPLS_LABELED (value 4) defined | `pathvector-types/src/afi.rs` | ✅ |
| MPLS label stack encoding in NLRI | `pathvector-session/src/message/update.rs` | ❌ Labels not parsed; NLRI treated as raw bytes |

---

## RFC 4364 — BGP/MPLS IP Virtual Private Networks (VPNs)

| Requirement | Module | Status |
|---|---|---|
| Safi::MPLS_VPN (value 128) defined | `pathvector-types/src/afi.rs` | ✅ |
| VPN-IPv4 address (8-byte RD + 4-byte prefix) NLRI encoding | `pathvector-session/src/message/update.rs` | ❌ Not implemented |
| Route Distinguisher type parsing | `pathvector-types` | ❌ No RD type |

---

## RFC 4761 — Virtual Private LAN Service (VPLS) Using BGP

| Requirement | Module | Status |
|---|---|---|
| Safi::VPLS (value 65), Afi::L2VPN (25) defined | `pathvector-types/src/afi.rs` | ✅ |
| VPLS NLRI encoding | `pathvector-session/src/message/update.rs` | ❌ Not implemented |

---

## RFC 7432 — BGP MPLS-Based Ethernet VPN (EVPN)

| Requirement | Module | Status |
|---|---|---|
| Safi::EVPN (value 70), Afi::L2VPN (25) defined | `pathvector-types/src/afi.rs` | ✅ |
| EVPN route type encoding (Type 1–5) | `pathvector-session/src/message/update.rs` | ❌ Not implemented |

---

## RFC 5575 — Dissemination of Flow Specification Rules (FlowSpec)

| Requirement | Module | Status |
|---|---|---|
| Safi::FLOW_SPEC (value 133) defined | `pathvector-types/src/afi.rs` | ✅ |
| FlowSpec NLRI component encoding (type, operator, value) | `pathvector-session/src/message/update.rs` | ❌ Not implemented |

---

## RFC 8654 — Extended Message Support for BGP

| Requirement | Module | Status |
|---|---|---|
| Extended Message capability (code 6) in OPEN | `pathvector-session/src/message/open.rs` | ❌ Not in capability decoder |
| When negotiated, allow UPDATE messages up to 65535 bytes | `pathvector-session/src/message/header.rs` | ❌ MAX_LEN is fixed at 4096 |

---

## RFC 7854 — BGP Monitoring Protocol (BMP)

| Requirement | Module | Status |
|---|---|---|
| BMP common header (version, length, type) | `pathvector-bmp/src/lib.rs` | ❌ Not started |
| Per-peer header (peer type, flags, peer address, AS, BGP ID, timestamp) | `pathvector-bmp/src/lib.rs` | ❌ Not started |
| Message type 0 — Route Monitoring: wraps BGP UPDATE | `pathvector-bmp/src/lib.rs` | ❌ Not started |
| Message type 1 — Statistics Report | `pathvector-bmp/src/lib.rs` | ❌ Not started |
| Message type 2 — Peer Down Notification | `pathvector-bmp/src/lib.rs` | ❌ Not started |
| Message type 3 — Peer Up Notification | `pathvector-bmp/src/lib.rs` | ❌ Not started |
| Message type 4 — Initiation Message | `pathvector-bmp/src/lib.rs` | ❌ Not started |
| Message type 5 — Termination Message | `pathvector-bmp/src/lib.rs` | ❌ Not started |
| Route Monitoring NLRI → `Route<A>` → `AdjRibIn` pipeline | `pathvector-bmp` / `pathvector-rib` | ❌ Not started |

---

## RFC 2385 — Protection of BGP Sessions via the TCP MD5 Signature Option

| Requirement | Module | Status |
|---|---|---|
| TCP-MD5 socket option set on eBGP peering connections | `pathvector-session/src/transport/mod.rs` | ❌ Not implemented |

---

## RFC 8205 — BGPsec Protocol Specification

| Requirement | Module | Status |
|---|---|---|
| BGPsec_PATH attribute (type 36): cryptographic path validation | `pathvector-types` / `pathvector-session` | ❌ Not started; noted as future work |

---

## Summary

| RFC | Subject | Overall Status |
|---|---|---|
| RFC 4271 | BGP-4 core protocol | ⚠️ Partial — best-path steps 1/3/7/8/9 and collision detection outstanding |
| RFC 2918 | Route Refresh | ✅ |
| RFC 3392 | Capability Advertisement | ✅ |
| RFC 4760 | Multiprotocol Extensions | ✅ |
| RFC 6793 | 4-Byte ASN | ✅ |
| RFC 4724 | Graceful Restart | ⚠️ Capability parsed; FSM restart behaviour not implemented |
| RFC 4486 | Cease NOTIFICATION Subcodes | ✅ |
| RFC 1997 | BGP Communities | ✅ |
| RFC 4360 | Extended Communities | ✅ |
| RFC 8092 | Large Communities | ✅ |
| RFC 7999 | BLACKHOLE Community | ⚠️ Value defined; discard action not wired |
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

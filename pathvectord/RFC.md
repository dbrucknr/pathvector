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
| LOCAL_PREF stripped when advertising to eBGP peers | `src/rib.rs` | ✅ | `test_local_pref_stripped_for_ebgp`, e2e: `test_e2e_full_route_lifecycle` |
| AS_PATH prepended with local ASN before advertising to eBGP peers | `src/rib.rs` | ✅ | `test_aspath_prepend_for_ebgp`, e2e: `test_e2e_full_route_lifecycle` |
| NEXT_HOP rewritten to local interface address for eBGP peers | `src/rib.rs` | ✅ | `test_next_hop_rewrite_for_ebgp` |
| NLRI batching: multiple prefixes packed into a single UPDATE when possible | `src/rib.rs` | ✅ | `test_nlri_batching_multiple_prefixes`, `test_nlri_batch_boundary_at_max_message_size` |
| Withdrawal sent to all peers when a best path is removed | `src/rib.rs` | ✅ | `test_withdrawal_propagated_to_all_peers`, e2e: `test_e2e_full_route_lifecycle` |
| Locally originated routes (PeerType::Local) not re-advertised to originating peer | `src/rib.rs` | ✅ | `test_local_routes_not_looped_back` |

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
| IPv4 unicast (AFI 1, SAFI 1): insert/withdraw prefix into Loc-RIB | `src/session_handler.rs` | ✅ | `test_ipv4_unicast_update_processed`, interop:gobgp |
| IPv6 unicast (AFI 2, SAFI 1) via MP_REACH_NLRI: insert/withdraw prefix into Loc-RIB | `src/session_handler.rs` | ✅ | `test_ipv6_unicast_update_processed` |
| Unknown AFI/SAFI: silently ignored (no session reset) | `src/session_handler.rs` | ✅ | `test_unknown_afisafi_ignored` |

---

## RFC 7999 — BLACKHOLE Community (Discard Action)

**Owns:** The discard action: when a received UPDATE contains BLACKHOLE community
(0xFFFF029A), the route is installed but traffic to the prefix is dropped (or delegated
to the kernel/FIB for a null route). Relies on `is_blackhole()` from `pathvector-types`
and `BlackholeCondition` from `pathvector-policy`.  
**Boundary:** The `BLACKHOLE` constant lives in `pathvector-types`. The policy condition
lives in `pathvector-policy`. The actual kernel null-route programming is deferred.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc7999

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Route with BLACKHOLE community installed in Loc-RIB with discard action | `src/session_handler.rs` | ✅ | `test_blackhole_route_installed` |
| Kernel null route programmed for BLACKHOLE prefix | — | ❌ | — |

**Deferred:** Kernel/FIB null-route programming requires a netlink or routing socket
abstraction. Currently the route is installed in Loc-RIB and can be exported via gRPC,
but no kernel forwarding entry is created.

---

## RFC 8212 — Default External BGP Route Propagation Without Policy

**Owns:** The default import/export policy when no policy is configured: reject all routes
from/to eBGP peers. Accept all routes from/to iBGP peers.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc8212

| Requirement | File | Status | Verified by |
|---|---|---|---|
| eBGP peers: reject all received routes when no import policy is configured | `src/session_handler.rs` | ✅ | `test_rfc8212_ebgp_reject_without_policy` |
| eBGP peers: reject all outbound routes when no export policy is configured | `src/rib.rs` | ✅ | `test_rfc8212_ebgp_no_export_without_policy` |
| iBGP peers: accept all received routes when no import policy is configured | `src/session_handler.rs` | ✅ | `test_rfc8212_ibgp_accept_without_policy` |

---

## RFC 4271 §8 — Connection Collision Coordination

**Owns:** The daemon-level decision of which session to keep when two peers simultaneously
open connections (collision detection and resolution). The FSM for each individual
session lives in `pathvector-session`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4271#section-8

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Detect when both the local and remote side open a connection to each other | `src/orchestrator.rs` | ✅ | `test_collision_detection` |
| Keep the connection initiated by the router with higher BGP Identifier | `src/orchestrator.rs` | ✅ | `test_collision_resolution_higher_bgp_id_wins` |
| Send NOTIFICATION Cease / Connection Collision Resolution on dropped connection | `src/orchestrator.rs` | ✅ | `test_collision_sends_cease_notification` |

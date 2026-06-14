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
| LOCAL_PREF stripped when advertising to eBGP peers | `src/outbound.rs` | ✅ | `test_prepare_outbound_ebgp_strips_local_pref` |
| AS_PATH prepended with local ASN before advertising to eBGP peers | `src/outbound.rs` | ✅ | `test_prepare_outbound_ebgp_prepends_local_as`, `test_propagate_prefix_ebgp_prepends_local_as_in_wire_message` |
| NEXT_HOP rewritten to TCP session local interface address for eBGP peers (RFC 4271 §5.1.3) | `src/outbound.rs`, `src/daemon.rs` | ✅ | `test_prepare_outbound_ebgp_rewrites_next_hop`, `test_on_established_ebgp_next_hop_uses_local_addr_not_router_id`, `test_propagate_to_all_peers_ebgp_next_hop_uses_local_addr`, e2e: `pathvectord_ebgp_next_hop_is_session_local_addr_not_router_id` |
| iBGP peers pass-through: LOCAL_PREF preserved, AS_PATH unchanged, NEXT_HOP unchanged | `src/outbound.rs` | ✅ | `test_prepare_outbound_ibgp_preserves_attributes` |
| Withdrawal sent to all peers when a best path is removed | `src/daemon.rs` | ✅ | `test_propagate_prefix_sends_withdraw_when_route_removed`, `test_on_terminated_propagates_withdraw_to_other_established_peers` |
| eBGP split-horizon: route received from eBGP peer not re-advertised back to that peer | `src/daemon.rs` | ✅ | `test_propagate_prefix_ebgp_source_peer_not_readvertised` |
| iBGP split-horizon: route received from iBGP peer not re-advertised to other iBGP peers | `src/daemon.rs` | ✅ | `test_propagate_prefix_ibgp_split_horizon_no_send`, `test_propagate_prefix_ibgp_split_horizon_eviction_sends_withdraw` |
| NLRI batching: announcements with same path attributes packed into fewest UPDATEs within `max_len` | `src/outbound.rs` | ✅ | `test_flush_same_attrs_batched_into_one_message`, `test_flush_splits_when_exceeding_max_len`, `test_flush_withdrawal_split_delivers_all_nlris` |
| Announcement groups with distinct path attributes go into separate UPDATEs | `src/outbound.rs` | ✅ | `test_flush_different_attrs_two_messages` |
| Withdrawals sent before announcements; withdrawal list packed within `max_len` | `src/outbound.rs` | ✅ | `test_flush_withdrawals_before_announces`, `test_flush_withdrawal_split_delivers_all_nlris` |

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
| IPv4 unicast inbound: insert/withdraw into Loc-RIB via traditional fields and MP_REACH_NLRI | `src/daemon.rs` | ✅ | `test_handle_update_mp_reach_announces_ipv4_route`, `test_handle_update_mp_unreach_withdraws_ipv4_route`, interop:gobgp |
| IPv4 unicast outbound: MP_REACH_NLRI (via `announced` field) + MP_UNREACH_NLRI with NEXT_HOP rewrite | `src/outbound.rs` | ✅ | `test_propagate_prefix_sends_update_for_new_route`, `test_propagate_prefix_sends_withdraw_when_route_removed`, interop:gobgp |
| IPv6 unicast inbound: MP_REACH_NLRI / MP_UNREACH_NLRI insert/withdraw into LocRib_v6 | `src/daemon.rs` | ✅ | `test_handle_update_mp_reach_ipv6_inserts_into_loc_rib_v6`, `test_handle_update_mp_unreach_ipv6_withdraws_route` |
| IPv6 unicast outbound: MP_REACH_NLRI with NEXT_HOP rewrite (eBGP); pass-through (iBGP) | `src/daemon.rs` | ✅ | `test_propagate_prefix_v6_ibgp_announces_route`, `test_propagate_prefix_v6_ebgp_with_local_ipv6_rewrites_nexthop` |
| Full-table dump on Established includes IPv6 routes | `src/daemon.rs` | ✅ | `test_on_established_sends_v6_full_table_dump` |
| Unknown AFI/SAFI: silently ignored (no session reset) | `src/daemon.rs` | ✅ | `test_handle_update_mp_unreach_non_ipv4_is_skipped` |

---

## RFC 7999 — BLACKHOLE Community (Discard Action)

**Owns:** The discard action: when a received UPDATE contains BLACKHOLE community
(0xFFFF029A), the route is stored in Adj-RIB-In but not installed in Loc-RIB (implicitly
discarded). Relies on `is_blackhole()` from `pathvector-types` and `BlackholeCondition`
from `pathvector-policy`.  
**Boundary:** The `BLACKHOLE` constant lives in `pathvector-types`. The policy condition
lives in `pathvector-policy`. The actual kernel null-route programming is deferred.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc7999

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Route with BLACKHOLE community stored in Adj-RIB-In but not installed in Loc-RIB | `src/daemon.rs` | ✅ | `test_handle_update_blackhole_route_stored_in_adj_rib_in`, `test_handle_update_blackhole_route_not_installed` |
| Kernel null route programmed for BLACKHOLE prefix | — | ❌ | — |

**Deferred:** Kernel/FIB null-route programming requires a netlink or routing socket
abstraction. Currently the route is rejected from Loc-RIB and can be inspected via
Adj-RIB-In, but no kernel forwarding entry is created.

---

## RFC 8212 — Default External BGP Route Propagation Without Policy

**Owns:** The default import/export policy when no policy is configured: reject all routes
from/to eBGP peers. Accept all routes from/to iBGP peers.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc8212

| Requirement | File | Status | Verified by |
|---|---|---|---|
| eBGP peers: reject all received routes when no import policy is configured | `src/daemon.rs` | ✅ | `test_daemon_state_new_ebgp_gets_reject_default_when_omitted`, `test_rfc8212_ebgp_ipv6_reject_without_policy` |
| eBGP peers: reject all outbound routes when no export policy is configured | `src/daemon.rs` | ✅ | `test_resolve_export_ebgp_omitted_defaults_to_reject`, `test_propagate_prefix_sends_withdraw_when_export_policy_rejects` |
| iBGP peers: accept all received routes when no import policy is configured | `src/daemon.rs` | ✅ | `test_resolve_import_ibgp_omitted_defaults_to_accept` |
| iBGP peers: accept all outbound routes when no export policy is configured | `src/daemon.rs` | ✅ | `test_resolve_export_ibgp_omitted_defaults_to_accept` |

---

## RFC 4456 — BGP Route Reflection

**Owns:** Route Reflector configuration, inbound attribute processing (ORIGINATOR_ID,
CLUSTER_LIST, loop detection), RR-aware iBGP split-horizon in the propagation loop, and
outbound inclusion of reflection attributes in UPDATE messages.  
**Boundary:** ORIGINATOR_ID / CLUSTER_LIST wire codec lives in `pathvector-session`.
Route struct fields for carrying the attributes live in `pathvector-rib`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4456

| Requirement | File | Status | Verified by |
|---|---|---|---|
| `is_rr_client` peer config flag + `cluster_id` daemon config | `src/config.rs` | ✅ | `test_config_rr_client_field_default_false` (config tests) |
| Loop detection: discard UPDATE if our `cluster_id` in CLUSTER_LIST | `src/daemon.rs` | ✅ | `test_rr_loop_detection_discards_update` |
| ORIGINATOR_ID set to client's BGP ID on first reflection | `src/daemon.rs` | ✅ | `test_rr_originator_id_and_cluster_list_set_on_reflected_route` |
| cluster_id prepended to CLUSTER_LIST on each reflection | `src/daemon.rs` | ✅ | `test_rr_originator_id_and_cluster_list_set_on_reflected_route` |
| Client → all other clients: reflect (not back to originating client) | `src/daemon.rs` | ✅ | `test_rr_client_route_reflected_to_other_client` |
| Client → non-client iBGP peers: reflect | `src/daemon.rs` | ✅ | `test_rr_client_route_reflected_to_non_client_ibgp` |
| Non-client iBGP → clients: reflect | `src/daemon.rs` | ✅ | `test_rr_non_client_ibgp_route_reflected_to_client` |
| Non-client iBGP → non-client iBGP: blocked (standard split-horizon) | `src/daemon.rs` | ✅ | `test_rr_non_client_ibgp_to_non_client_ibgp_still_blocked` |
| ORIGINATOR_ID + CLUSTER_LIST included in outbound UPDATE attributes | `src/outbound.rs` | ✅ | `test_rr_originator_id_and_cluster_list_set_on_reflected_route` |

---

## RFC 4271 §8 — Connection Collision Coordination

**Owns:** The FSM-level decision of which session to keep when two peers simultaneously
open connections (collision detection and resolution). In pathvectord, this is delegated
to the `pathvector-session` transport layer via `SessionHandle`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc4271#section-8

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Detect when both the local and remote side open a connection to each other | `pathvector-session/src/transport/mod.rs` | ✅ | `test_collision_in_open_confirm_peer_bgp_id_higher_rejects_incoming` (in `pathvector-session`) |
| Keep the connection initiated by the router with higher BGP Identifier | `pathvector-session/src/transport/mod.rs` | ✅ | `test_collision_in_open_confirm_peer_bgp_id_higher_rejects_incoming` (in `pathvector-session`) |
| Send NOTIFICATION Cease / Connection Collision Resolution on dropped connection | `pathvector-session/src/transport/mod.rs` | ✅ | — |

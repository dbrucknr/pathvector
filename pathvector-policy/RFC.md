# RFC Requirements — pathvector-policy

This crate owns the **policy engine**: condition evaluation, action application, and
term-list execution semantics. It operates on route attributes already parsed into
`pathvector-types` structs and has no wire protocol knowledge and no RIB state.

**Status key:** ✅ Implemented and tested | ⚠️ Partial — see notes | ❌ Not started  
**Verified by key:** `test_name` — unit test | `proptest` — property test | `—` — no automated verification

---

## RFC 1997 — BGP Communities Attribute (Policy Layer)

**Owns:** Community match conditions and community mutation actions. The `Community` type
and well-known constants live in `pathvector-types`; wire encoding lives in
`pathvector-session`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc1997

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Match condition: route carries a specific community value | `src/condition.rs` | ✅ | `test_community_match_condition_true`, `test_community_match_condition_false` |
| Match condition: route carries any well-known community | `src/condition.rs` | ✅ | `test_well_known_community_match` |
| Action: add community to route | `src/action.rs` | ✅ | `test_community_add_action` |
| Action: remove community from route | `src/action.rs` | ✅ | `test_community_remove_action` |
| Action: set (replace) entire community list | `src/action.rs` | ✅ | `test_community_set_action` |

---

## RFC 8092 — BGP Large Communities Attribute (Policy Layer)

**Owns:** Large community match conditions and large community mutation actions. The
`LargeCommunity` type lives in `pathvector-types`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc8092

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Match condition: route carries a specific large community (global:local1:local2) | `src/condition.rs` | ✅ | `test_large_community_match_condition_true`, `test_large_community_match_condition_false` |
| Action: add large community to route | `src/action.rs` | ✅ | `test_large_community_add_action` |
| Action: remove large community from route | `src/action.rs` | ✅ | `test_large_community_remove_action` |

---

## RFC 7999 — BLACKHOLE Community (Policy Integration)

**Owns:** The policy integration point: `is_blackhole()` used as a built-in condition that
matches when a route carries community 0xFFFF029A.  
**Boundary:** The `BLACKHOLE` constant and `is_blackhole()` predicate live in
`pathvector-types`. The discard action that drops traffic for BLACKHOLE routes is wired
in `pathvectord`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc7999

| Requirement | File | Status | Verified by |
|---|---|---|---|
| `BlackholeCondition` matches routes carrying BLACKHOLE community (0xFFFF029A) | `src/condition.rs` | ✅ | `test_blackhole_condition_matches`, `test_blackhole_condition_no_match` |

---

## RFC 9234 — Route Leak Prevention Using Roles in UPDATE and OPEN Messages

**Owns:** `OtcLeakCondition` (RFC 9234 §5 ingress leak detection),
`OtcPropagationCondition` (§6 egress block), and `SetOtc` (§5/§6 attach-if-absent,
used at both the ingress and egress call sites with different ASN arguments) — all
in `src/otc.rs`.  
**Boundary:** OTC wire encode/decode and role-pair OPEN validation are in
`pathvector-session`. OTC storage on `Route<A>` is in `pathvector-rib`. Deciding
*which* peers get these terms installed, and with what `session_role`/ASN
arguments, is in `pathvectord`.  
**Datatracker:** https://datatracker.ietf.org/doc/html/rfc9234

All three types are keyed off `session_role` — the role the local speaker plays on
a given session (configured per peer, not per-AS). `session_role` describes *our*
role; the peer's implied role is always the complement. RFC 9234's own rule text is
phrased in terms of the peer's role ("route from Customer", "advertised to
Provider") — every doc comment in `src/otc.rs` translates that into `session_role`
explicitly, since getting this backwards silently inverts the whole leak-prevention
mechanism (caught and corrected during this feature's own development — see
`src/otc.rs`'s module doc comment).

| Requirement | File | Status | Verified by |
|---|---|---|---|
| Ingress leak detection: `session_role` Provider/RouteServer + OTC present → leak | `src/otc.rs` | ✅ | `provider_role_with_otc_present_is_a_leak_regardless_of_value`, `route_server_role_with_otc_present_is_a_leak` |
| Ingress leak detection: `session_role` Peer + OTC present with wrong ASN → leak | `src/otc.rs` | ✅ | `peer_role_with_wrong_otc_asn_is_a_leak`, `peer_role_with_matching_otc_asn_is_not_a_leak` |
| OTC absent, or `session_role` Customer/RsClient with OTC present, never flagged as a leak | `src/otc.rs` | ✅ | `provider_or_route_server_role_without_otc_is_not_a_leak`, `peer_role_without_otc_is_not_a_leak`, `customer_and_rs_client_roles_with_otc_present_are_not_flagged` |
| Egress block: route already carrying OTC matches `OtcPropagationCondition` | `src/otc.rs` | ✅ | `propagation_condition_matches_iff_otc_present` |
| `SetOtc` attaches when absent, is idempotent (never overwrites an existing value) | `src/otc.rs` | ✅ | `set_otc_attaches_when_absent`, `set_otc_is_idempotent_never_overwrites_existing_value` |
| End-to-end through a `Policy`: ingress reject/attach, egress block/attach | `src/otc.rs` | ✅ | `ingress_policy_rejects_leak_accepts_and_attaches_otherwise`, `ingress_policy_attaches_peer_asn_when_session_role_is_customer`, `egress_policy_blocks_propagation_to_provider_when_otc_already_set`, `egress_policy_attaches_local_asn_when_session_role_is_provider` |
| Generic over any `BgpRoute` impl — works for IPv6 routes, not just the IPv4 `TestRoute` | `src/otc.rs` | ✅ | `v6_leak_detection_and_attach_work_identically` |

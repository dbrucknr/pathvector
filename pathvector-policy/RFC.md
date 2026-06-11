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

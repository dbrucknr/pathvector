# RFC Compliance Audit Log

This file logs systematic, clause-by-clause audit passes over each RFC this
project claims to implement. It answers a different question than the other
two RFC docs in this repo:

- **`RFC_REQUIREMENTS.md`** (root) — one-line-per-RFC index of aggregate
  status (✅/⚠️/❌), for a quick "what's the overall coverage" glance.
- **Per-crate `RFC.md`** — "what we built and how it's tested," organized by
  requirement, populated *while building* a feature.
- **This file** — "has anyone actually gone back through the spec text
  clause-by-clause and checked it against the code, and what did they find."
  Neither of the other docs captures that a requirement was never on the
  checklist in the first place — which is exactly what hid two real bugs
  found in July 2026 (a missing RFC 4271 §6.1 NOTIFICATION and a missing
  ConnectRetryTimer re-arm on `HoldTimerExpired`) through 289 pre-existing
  unit tests and prior e2e runs. Both only surfaced via deliberate
  fault-injection testing, not a spec re-read — this audit is the spec
  re-read that should have caught them sooner.

**This audit is diagnostic only.** It finds and records; it does not fix.
Bug fixes get their own scoped PR with a regression test, decided on their
own merits — not bundled into audit output. Every finding lands in exactly
one of three buckets:

- **Confirmed correct** — code and tests both verified against the actual
  clause text, not just a same-area test with a plausible-sounding name.
- **Confirmed gap** — a specific missing/wrong code path, pointed to by file
  and function, not a vague suspicion. Gets a `TODO.md` entry linking back
  to its row here.
- **Needs investigation** — evidence points one way but isn't conclusive.
  Stays here only, as an open question, until resolved one way or the other.

## Roadmap

Prioritized by risk (state-machine-shaped code that's hard to test
exhaustively) and blast radius, not by RFC number:

1. **RFC 4271 (full)** — in progress. Core protocol; already proven to hide
   bugs in exactly this way.
2. RFC 4724 (Graceful Restart) — was audited once before (see project
   history), but that pass predates this log and wasn't recorded
   clause-by-clause; worth a fresh, logged pass.
3. RFC 9234 (Route Leak Prevention/Roles) — newest substantial feature,
   least battle-tested.
4. RFC 7606 (revised UPDATE error handling) — directly adjacent to the
   §6.1 fix; worth confirming there's no similar gap between them.
5. The already-flagged ⚠️ items in `RFC_REQUIREMENTS.md`: RFC 5492
   (capabilities), RFC 6793 (4-octet AS), RFC 4271 §9.1/§9.2 (decision
   process/MRAI — partially covered by #1), RFC 6396 (MRT write side).
6. RPKI (RFC 6810/6811/8210) and the BMP scaffold (RFC 7854) — lower
   priority; less state-machine-shaped.
7. Attribute/encode-only RFCs (1997, 4360, 8092, SAFI-constant RFCs, 6996,
   1930, 5065) — lowest audit value; mostly static encode/decode already
   covered by round-trip tests and proptests. Quick pass, not deep.

---

## RFC 4271 — A Border Gateway Protocol 4 (BGP-4)

**Audit started:** 2026-07-16
**Method:** Full text fetched from rfc-editor.org/rfc/rfc4271 (not relied on
from memory), read section by section; every MUST/SHOULD/MAY cross-checked
against implementation in `pathvector-session`, `pathvector-rib`,
`pathvectord`, and against what the existing test suite actually exercises
(not just what a test's name implies).
**Status:** In progress — §4 (Message Formats) complete below; §1–3, §5–10
not yet covered by this pass.

### §4.1 — Message Header Format

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| Marker MUST be all-ones | Confirmed correct | `header.rs:59` checks `marker != MARKER` before anything else | `test_decode_header_invalid_marker`, `test_invalid_marker_sends_message_header_notification` |
| Length MUST be ≥19 and ≤4096 (or ≤65535 under RFC 8654) | Confirmed correct | `header.rs:63` bounds-checks against `max_len` | `test_decode_header_length_too_small`, `test_decode_header_length_too_large`, `test_decode_header_length_valid_in_extended_mode` |
| Type MUST be a recognized code | Confirmed correct | `MessageType::from_u8` rejects unknown codes | `test_decode_header_unknown_type`, `test_unknown_message_type_sends_message_header_notification_with_type_in_data` |
| Length field MUST have the smallest value required — "padding of extra data after the message is not allowed" | **Confirmed gap** | `decode_with_limit` (`message/mod.rs:216-248`) only checks the *outer* buffer length matches the header's declared total (`buf.len() != total_len`, line 220) and, for `Keepalive` only, that the cursor is fully drained afterward (line 241, `cur.remaining() != 0`). The `Open` (`open.rs:39-57`) and `RouteRefresh` (`route_refresh.rs:75-83`) decoders read their known fixed+declared-length fields and stop — nothing checks the cursor is empty afterward, so an OPEN or ROUTE-REFRESH message with the header's Length field padded past the real body (extra trailing bytes inside the frame) is silently accepted, with the padding silently discarded. `Update` and `Notification` are not affected: `Update`'s NLRI field has no separate length prefix by design (RFC 4271 §4.3 defines it as consuming the rest of the message), so full-cursor consumption there is correct, not incidental; `Notification`'s Data field is explicitly variable-length and consumes the remainder by design (`notification.rs:22`, `read_remaining()`). | A test sending a well-formed OPEN (or ROUTE-REFRESH) with extra trailing garbage bytes inside the declared header Length, asserting decode returns an error (e.g. reusing `CodecError::InvalidLength` or a new variant) instead of silently succeeding — then add the `cur.remaining() != 0` check to the `Open` and `RouteRefresh` arms in `decode_with_limit`, mirroring the existing `Keepalive` arm. Low severity (permissiveness, not corruption or crash) but a clear, mechanically fixable RFC violation. |

**Summary so far:** 4 clauses reviewed — 3 confirmed correct, 1 confirmed
gap.

### §4.2 — OPEN Message Format

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| Hold Time MUST be either zero or at least three seconds (i.e. 1 and 2 are the only invalid non-zero values) | Confirmed correct | `fsm/mod.rs:680` — `if peer.hold_time == 1 \|\| peer.hold_time == 2` sends `NotificationError::OpenMessage(OpenMsgError::UnacceptableHoldTime)`; code read directly, single unambiguous condition covering both invalid values symmetrically | `test_unacceptable_hold_time_sends_notification` (`fsm/mod.rs:1144`) exercises hold_time=1 only, not 2 — code inspection makes a typo-style asymmetry unlikely here (one `if` condition, not two separate match arms like the `HoldTimerExpired` bug), but a second test asserting hold_time=2 is also rejected would make this fully test-proven rather than proven-by-inspection |
| BGP Identifier MUST be assigned to the sender and the same for every local interface and peer | Confirmed correct | `pathvectord/src/daemon/mod.rs:701,974` — `local_bgp_id` is read once from `cfg.daemon.bgp_id` at startup and threaded through to RIB/session construction (`local_bgp_id` field, `daemon/mod.rs:163`); every peer session is built from the same `DaemonState`/`Rib` instance, so all peers see the same value | `test_rr_originator_id_falls_back_to_local_bgp_id_when_peer_bgp_id_unknown` and the broader RR/OriginatorId test suite indirectly confirm a single consistent value; no test explicitly spins up 2+ peers and asserts identical `bgp_id` in both OPENs, but the single-assignment-point code structure makes this low-risk |
| Minimum OPEN message length is 29 octets | Confirmed correct | Not an explicit checked constant — enforced structurally: `OpenMessage::decode` (`open.rs:39-49`) reads version(1)+my_as(2)+hold_time(2)+bgp_id(4)+opt_len(1) = 10 fixed bytes; header(19)+10 = 29. Any declared header Length below 29 leaves too few body bytes, so a fixed-field `read_u16`/`read_ipv4addr` call hits `CodecError::Truncated` before the message can be assembled | `test_decode_header_length_too_small` combined with the field-level `Cursor::read_*` truncation checks; no single test constructs a 20-28 byte OPEN specifically, but the mechanism is structural rather than a fallible explicit check, so the residual risk is low |

**§4.2 summary:** 3 clauses reviewed — all confirmed correct (2 with a minor
test-coverage caveat noted above, not a code concern).

### §4.3 — UPDATE Message Format

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| For well-known attributes, the Transitive bit MUST be 1; for well-known and optional-non-transitive attributes, the Partial bit MUST be 0 ("Attribute Flags Error", also enumerated as UPDATE Message Error subcode 4 in §4.5/§6.3) | **Confirmed gap** | `decode_attr_value` (`update.rs:332-543`) receives the `flags` byte for every attribute but only ever uses it for the `Unknown` (unrecognized type) fallback case (line ~536, to preserve flags for possible re-transmission) — for every *known* type (ORIGIN, AS_PATH, NEXT_HOP, MED, LOCAL_PREF, OTC, ATOMIC_AGGREGATE, AGGREGATOR, COMMUNITY, etc.) the flags bits are read off the wire and then never checked against what that attribute type is supposed to have. `UpdateMsgError::AttributeFlagsError` exists in `notification.rs:190` (needed to decode a NOTIFICATION a peer might send us) but grepping the whole workspace shows it is only ever *constructed* in two proptest `Arbitrary` generators (`message/prop_tests.rs:171`, `framing/prop_tests.rs:151`) for round-tripping NOTIFICATIONs we might receive — never by our own UPDATE decoder. A peer sending, e.g., ORIGIN with the Optional bit set, or LOCAL_PREF marked non-transitive, would have that attribute silently accepted as-is. | A test sending each of ORIGIN/AS_PATH/NEXT_HOP with a flags byte violating its required flags (e.g. ORIGIN with `FLAG_OPTIONAL` set instead of `FLAG_TRANSITIVE`), asserting `AttributeFlagsError` is produced — then wire up the check. **Caveat:** RFC 7606 (§4) revises which UPDATE Message Errors trigger session reset vs. "treat-as-withdraw"; the RFC 7606 audit pass (roadmap #4) should confirm whether it changes the *severity* of an Attribute Flags Error specifically, since this pass only confirms the base RFC 4271 requirement is unimplemented, not what the correct modern remediation looks like. |
| Withdrawn Routes and NLRI SHOULD NOT contain the same prefix in one UPDATE; if they do, a BGP speaker MUST be able to process it and SHOULD treat it as if WITHDRAWN did not contain that prefix (i.e., net effect = announced) | Needs investigation | `handle_update` (`pathvectord/src/daemon/route.rs`) processes `msg.withdrawn` first (line 904, calling `adj_rib_in.withdraw`/`loc_rib.withdraw`) and applies `msg.announced` afterward in a later, unified loop (line 1133, via `all_announced`) — this ordering means a same-prefix overlap would naturally resolve to "announced," matching the RFC's SHOULD. However, this is a byproduct of code order, not an explicit same-prefix check, and no test exercises this exact scenario (a single UPDATE with the same prefix in both `withdrawn` and `announced`) — so per this audit's own standard, "looks right by inspection" isn't enough to mark it confirmed. | A dedicated test constructing one UPDATE with prefix X in both `withdrawn` and `announced`, asserting the final RIB/AdjRibIn state has X present (announced), not absent. |
| Minimum UPDATE message length is 23 octets | Confirmed correct | Same structural argument as OPEN's 29-octet minimum (§4.2): `withdrawn_len`/`attrs_len` reads (`update.rs:148,154`) require 2+2 bytes to exist in the body; insufficient bytes surface as `CodecError::Truncated` before a message can be assembled. No explicit constant-check, but no code path can produce a message shorter than 23 octets and have it parse successfully. | — |
| NLRI length is derived by subtraction (`total_len - 23 - attrs_len - withdrawn_len`), not an explicit field | Confirmed correct | `decode_nlri_list_v4(cur)` (`update.rs:159,206-212`) consumes the outer cursor until `cur.remaining() == 0` — since `withdrawn`/`attributes` are parsed via bounded `fork()` sub-cursors that advance the parent cursor by exactly their declared lengths, whatever remains in the parent cursor after both forks *is* exactly the RFC's subtraction formula, by construction rather than by explicit arithmetic | `test_update_roundtrip`, `test_update_empty`, interop:gobgp (per `pathvector-session/RFC.md` §4) |

**§4.3 summary:** 4 clauses reviewed — 2 confirmed correct, 1 confirmed gap,
1 needs investigation.

### §4.4 — KEEPALIVE Message Format

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| KEEPALIVE consists of only the message header, no body (implies Length MUST always be exactly 19 for this type) | Confirmed correct | `decode_with_limit`'s `Keepalive` arm (`message/mod.rs:240-245`) explicitly checks `cur.remaining() != 0` and errors — the one message type that *does* have the "no trailing bytes" check that OPEN/ROUTE_REFRESH lack (see §4.1 finding above) | `test_decode_header_keepalive`, `test_encode_keepalive_produces_19_bytes` |

**§4.4 summary:** 1 clause reviewed — confirmed correct.

### §4.5 — NOTIFICATION Message Format

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| Error Code / Error Subcode / Data layout; Data length derivable as `Message Length - 21` | Confirmed correct | `notification.rs:19-23` reads code(1)+subcode(1) then `read_remaining()` for Data — Data is defined as "whatever's left," so full-cursor consumption here is correct by design, unlike OPEN/ROUTE_REFRESH's gap in §4.1 | `test_notification_roundtrip`, `test_notification_cease` |
| Minimum NOTIFICATION length is 21 octets | Confirmed correct | Same structural argument as §4.2/§4.3: code+subcode reads require 2 bytes to exist in the body; insufficient bytes error out via `Truncated` before assembly | — |
| Error Code/Subcode enumeration (Message Header 1, OPEN 2, UPDATE 3, Hold Timer Expired 4, FSM Error 5, Cease 6) matches RFC table | Confirmed correct | Cross-checked `notification.rs`'s `NotificationError`/`*Error` enums and `from_u8`/`as_u8` mappings against the RFC 4271 §4.5 table verbatim — codes and subcodes match, including the RFC-noted gaps (subcode 5 under OPEN Message Error is `[Deprecated]` and subcode 7 under UPDATE Message Error is `[Deprecated]`, both correctly absent from the active mapping) | `test_notification_roundtrip` plus the various `*_sends_notification` tests across `fsm/mod.rs` exercising individual subcodes |

**§4.5 summary:** 3 clauses reviewed — all confirmed correct.

### §4 (Message Formats) running total

15 clauses reviewed across §4.1–§4.5 — 12 confirmed correct, 2 confirmed
gaps, 1 needs investigation.

---

*(Sections §1–3 and §5–§10 not yet covered by this audit pass — continuing
in subsequent sessions per the roadmap above. This file will be updated
incrementally rather than all at once, so a partial, in-progress state here
is expected, not a sign the audit was abandoned.)*

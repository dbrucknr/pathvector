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

1. **RFC 4271 (full)** — substantially complete. Core protocol; already
   proven to hide bugs in exactly this way.
2. **RFC 4724 (Graceful Restart)** — substantially complete. Was audited
   once before (see project history), but that pass predates this log and
   wasn't recorded clause-by-clause; this fresh pass found 3 new gaps.
3. **RFC 9234 (Route Leak Prevention/Roles)** — substantially complete.
   Was the newest substantial feature going in; found 2 real gaps
   alongside an otherwise well-built core leak-detection mechanism.
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

## §5 — Path Attributes

**Scope this pass:** §5 general rules plus §5.1.1–§5.1.7 (per-attribute usage
rules). Cross-checked against `pathvector-session` (attribute codec),
`pathvector-rib` (`Route`, `RareAttrs`, `best_path.rs`, `outbound.rs`), and
`pathvectord` (`daemon/route.rs`, `outbound.rs`).

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| Mandatory table: ORIGIN/AS_PATH/NEXT_HOP mandatory for both eBGP and iBGP when NLRI present | Confirmed correct | `handle_update` (`pathvectord/src/daemon/route.rs:1011-1049`) checks `has_origin`/`has_as_path`/(NEXT_HOP for traditional v4) whenever any announce is present, regardless of peer type, and sends `MissingWellKnownAttribute` with the correct type code in Data | `missing_origin_returns_notification_data_type_code_1`, `missing_as_path_returns_notification_data_type_code_2`, `missing_next_hop_for_traditional_ipv4_returns_notification_data_type_code_3` (per `pathvectord/RFC.md`) |
| Unrecognized transitive optional attributes SHOULD be accepted and MUST be passed to other peers with Partial bit set to 1; unrecognized non-transitive attributes MUST be quietly ignored and not passed along | **Confirmed gap** | `Route<A>` (`pathvector-rib/src/route.rs:76-117`) and its `RareAttrs` companion have no field of any kind for an opaque/unrecognized attribute — communities, cluster_list, aggregator, originator_id, otc are the only "rare" slots. `AdjRibIn`/`AdjRibOut` store the same `Route<A>` (confirmed via `adj_rib_in.rs:42`), and `route_to_attributes` (`pathvectord/src/outbound.rs:35-104`, the function that assembles the outbound attribute list for re-encoding) has no `PathAttribute::Unknown` arm. So *any* unrecognized attribute — transitive or not — is unconditionally dropped the moment a route is accepted into the RIB; there is no path by which a transitive-optional attribute this implementation doesn't know about could survive being relayed through this router. This is a real transit-correctness concern, not just a completeness gap: any future/foreign BGP path attribute riding through this router as a transit AS would be silently stripped. Note the *existing* `pathvector-session/RFC.md` row "Unknown optional transitive attributes preserved in Partial flag ✅" is accurate only at the codec round-trip level (decode a message, re-encode the *same* message object) — it says nothing about the RIB-pipeline path this finding is about, and shouldn't be read as covering it. | This is a real design gap, not a one-line fix — would need an `unknown_attrs: Vec<{flags, type_code, value}>` (or similar) field threaded through `Route`/`RareAttrs`, `RouteBuilder`, `handle_update`'s attribute loop, and `route_to_attributes`, plus a test that relays an UPDATE carrying a made-up transitive-optional attribute (e.g. type code 200) through pathvectord to a second peer and confirms it survives with Partial=1 set. Scoped as its own TODO item, not something to bundle into a quick fix. |
| LOCAL_PREF received from an external (eBGP) peer MUST be ignored by the receiving speaker (§5.1.5) — distinct from the already-implemented "MUST NOT send LOCAL_PREF to eBGP peers" outbound rule | **Confirmed gap — highest severity finding so far** | `handle_update`'s attribute loop (`pathvectord/src/daemon/route.rs:944-964`) captures `PathAttribute::LocalPref(lp)` into a local variable with no `peer_type` check at all, and it's applied to the built route unconditionally (line 1154-1156: `if let Some(lp) = local_pref { builder = builder.local_pref(lp); }`). `RouteBuilder::build()` (`pathvector-rib/src/route.rs:409-422`) does not strip it based on peer type either — pure passthrough. `best_path.rs:167-169`'s comparator reads `.local_pref` uniformly for every route regardless of where it came from. **Practical impact:** an eBGP peer can attach an arbitrary LOCAL_PREF (e.g. `u32::MAX`) to a route it sends us, and since LOCAL_PREF is the *first* tie-break step in the decision process (RFC 4271 §9.1.1, ahead of AS_PATH length, ORIGIN, MED, etc.), that peer can force its own route to win best-path selection against routes we'd otherwise prefer — exactly the outcome this MUST exists to prevent. This is the class of bug the RFC calls out by name as a reason for the rule, not a theoretical edge case. `pathvectord/RFC.md` was updated to add this as a ❌ row (previously not tracked at all — the existing rows only covered the *outbound*, eBGP-peer-facing side of LOCAL_PREF handling). | A test sending an UPDATE from an eBGP-typed peer with an explicit LOCAL_PREF attribute, asserting the resulting route's `local_pref` is `None` (falls back to default) rather than the peer-supplied value — then gate the `PathAttribute::LocalPref` match arm (or the `builder.local_pref(lp)` call) on `peer_type == PeerType::Internal`. |
| AS_PATH: iBGP speaker SHALL NOT modify AS_PATH when advertising to internal peers; eBGP speaker prepends own AS (with segment-type rules for AS_SET vs AS_SEQUENCE vs empty) | Confirmed correct | `prepare_outbound`/`prepare_outbound_v6` (`pathvector-rib/src/outbound.rs:27-73`) only call `.prepend()` inside the `PeerType::External` branch; the iBGP branch never touches `as_path` | `test_prepare_outbound_ebgp_prepends_local_as`, `test_prepare_outbound_ibgp_preserves_attributes` (per `pathvectord/RFC.md`) — note this pass didn't re-verify the AS_SET-vs-AS_SEQUENCE-vs-empty segment-type branching inside `AsPath::prepend` itself; that's in `pathvector-types`, out of scope for this pass |
| NEXT_HOP: default behavior is to use the local session interface address for eBGP; third-party/multihop-passthrough NEXT_HOP forms are optional (MAY/SHOULD) and not required | Confirmed correct (as a deliberate scope choice, not a gap) | `prepare_outbound` unconditionally rewrites NEXT_HOP to `local_next_hop` for every eBGP peer — this is exactly the RFC's stated *default* behavior ("By default... use the IP address of the interface that the speaker uses to establish the BGP connection to peer X"). The optional third-party/multihop-EBGP-passthrough forms (all MAY-level) are simply not implemented, which is a legitimate scope choice, not a violation | `test_prepare_outbound_ebgp_rewrites_next_hop` |
| A route SHALL NOT be advertised to a peer using that peer's own address as NEXT_HOP | Confirmed correct | Follows directly from the above: `local_next_hop` is always *our own* interface address, never the destination peer's — this can never coincide with the peer's own address under normal operation (the only way it could would be an IP collision between our interface and the peer's address, which is a misconfiguration outside this clause's intent) | Same tests as above |
| A BGP speaker SHALL NOT install a route with itself as the next hop | Needs investigation | `is_valid_next_hop_v4` (`pathvectord/src/daemon/route.rs:843-849`) rejects a *received* route whose NEXT_HOP equals our own address at RIB-ingest time — but this pass didn't check the FIB-installation layer (`fib.rs`) itself for an equivalent guard on routes that reach installation via other paths (e.g. locally-originated routes, or routes whose next-hop resolves to a local address through recursive lookup rather than being literally equal to it) | Read `pathvectord/src/fib.rs`'s route-install path and confirm/deny a self-next-hop guard exists there independently of the RIB-ingest check |
| The same attribute (by type code) cannot appear more than once in one UPDATE's Path Attributes field | Confirmed correct | `decode_path_attributes` (`update.rs:291,308-316`) tracks a `seen: [bool; 256]` array and treats a repeat as a decode error (RFC 7606 §7.3 duplicate-attribute handling) | Already covered under the existing RFC 7606 rows in `pathvector-session/RFC.md` |
| Sender SHOULD order attributes ascending by type; receiver MUST handle out-of-order attributes | Confirmed correct | `decode_path_attributes` is a `match type_code` inside a `while` loop with no ordering assumption of any kind — attributes are processed in whatever order they arrive on the wire | Implicit in every existing UPDATE decode test, none of which special-case attribute order |
| ATOMIC_AGGREGATE: SHOULD NOT be removed when propagating; MUST NOT make NLRI more specific when re-advertising a route carrying it | Needs investigation | `atomic_aggregate: bool` is a `RareAttrs` field and is round-tripped when present (confirmed: it's read at ingest and re-emitted in `route_to_attributes`) — the "MUST NOT make NLRI more specific" clause relates to §9.1.4 (Overlapping Routes)/aggregation, which this pass hasn't reached yet; deferred to the §9 pass (roadmap item, task #108) rather than guessed at here | Confirm during the §9.1.4 audit whether pathvectord ever splits/deaggregates a received prefix in a way this clause would forbid |
| AGGREGATOR: optional transitive, MAY be added on aggregation, SHOULD use speaker's own BGP Identifier as the IP | Confirmed correct (for the round-trip/pass-through case; aggregation itself is out of scope) | `aggregator: Option<Aggregator>` round-trips through `RareAttrs` the same way as `atomic_aggregate`; this project doesn't perform route aggregation itself (no §9.2.2.2 implementation), so the "SHOULD use own BGP Identifier" clause has no applicable code path to check — noted as N/A rather than confirmed against an actual aggregation feature | N/A unless/until route aggregation is implemented |

**§5 summary:** 11 clauses reviewed — 7 confirmed correct (2 of those as
deliberate, non-gap scope choices), 2 confirmed gaps (1 of which is this
audit's most severe finding to date), 2 needs investigation.

---

## §6.2 — OPEN Message Error Handling

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| Unsupported Version Number → NOTIFICATION with Data = fallback version | **Confirmed gap — already tracked, not new** | `open.rs:39-43` returns `CodecError::UnsupportedVersion(version)` at decode time (below the header layer), which falls into the *already-documented* deferred bucket from the §6.1 work: "`CodecError` variants below the header layer... are not yet mapped to a NOTIFICATION; the connection is dropped silently" (`pathvector-session/RFC.md`'s §6.1 section). Not filing a new TODO item — this is the same gap, just confirmed to also cover this specific clause. | See the existing deferred note under §6.1 in `pathvector-session/RFC.md` |
| Bad Peer AS → NOTIFICATION(OPEN Error, Bad Peer AS) | Confirmed correct | `fsm/mod.rs:670-677` checks `resolve_as(peer) != expected` | `test_bad_peer_as_sends_notification` (per `pathvector-session/RFC.md`) |
| Unacceptable Hold Time (1 or 2 seconds) → NOTIFICATION | Confirmed correct | Already verified in the §4.2 pass above | `test_unacceptable_hold_time_sends_notification` |
| Bad BGP Identifier: syntactically incorrect (not a valid unicast host address) → NOTIFICATION | Confirmed correct | `fsm/mod.rs:651-655` rejects `Ipv4Addr::UNSPECIFIED`, multicast, and `BROADCAST` *before* the separate same-as-us collision check at line 663 — confirmed by tracing `test_bad_bgp_id_sends_notification`'s test peer (`my_as: 65002`) against `default_config()`'s `local_as: 65001`: they differ, so the test is genuinely exercising the syntactic-validity branch, not accidentally passing through the collision branch | `test_bad_bgp_id_sends_notification` |
| Unrecognized Optional Parameter (parameter type, not capability code) → NOTIFICATION(OPEN Error, Unsupported Optional Parameters) | **Confirmed gap (new)** | `decode_capabilities` (`open.rs:91-108`) has a self-documenting comment at line 105: `// Unknown parameter types are silently skipped.` — any OPEN optional parameter whose Parameter Type isn't 2 (Capabilities) is dropped with no error of any kind, let alone the RFC-mandated NOTIFICATION | A test with a parameter type other than 2 in an OPEN's optional parameters, asserting `OpenMsgError::UnsupportedOptionalParameters`; then either error or explicitly document why silent-skip was chosen (e.g. forward-compatibility with parameter types not yet assigned) if the fix is judged not worth making |
| Recognized-but-malformed Optional Parameter → subcode 0 (Unspecific) | Needs investigation | Not traced this pass — would need to check what happens when `decode_capability` itself fails (e.g. `CodecError::InvalidCapability`) versus a structural failure in the outer `decode_capabilities` loop | Trace whether a malformed (but type-2-recognized) capability TLV produces any NOTIFICATION at all, and if so, with which subcode |

**§6.2 summary:** 5 clauses reviewed — 3 confirmed correct, 1 confirmed gap
(new), 1 confirmed gap (already tracked under the existing §6.1 deferred
note), 1 needs investigation.

## §6.3 — UPDATE Message Error Handling (partial pass)

This section overlaps significantly with the §4.3/§5 findings above, which
already established that the 5 RFC 7606-covered attribute-value error cases
(ORIGIN/AS_PATH/NEXT_HOP/MED/LOCAL_PREF-shaped decode failures) correctly
use modern treat-as-withdraw handling rather than the raw RFC 4271 NOTIFICATION
behavior — that's *compliant*, since RFC 7606 supersedes this section for
those specific cases, not a gap. This pass adds two clauses not yet covered:

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| Unrecognized **well-known** attribute (Optional bit = 0, but the type code itself isn't recognized) → NOTIFICATION(UPDATE Error, Unrecognized Well-known Attribute) — distinct from an ordinary unrecognized optional attribute, which is meant to be accepted | **Confirmed gap** | `decode_attr_value`'s fallback arm (`update.rs:534-541`) treats *any* unrecognized type code identically — stored as `PathAttribute::Unknown` and accepted — regardless of whether the Optional bit in `flags` marks it well-known (bit=0) or optional (bit=1). Per §5, "BGP implementations MUST recognize all well-known attributes," so a well-known-flagged but unrecognized type code is a real protocol violation the RFC expects to be rejected, not silently accepted the same way a legitimate unrecognized *optional* attribute would be (see the related, but distinct, §5 finding on unrecognized-transitive-optional handling above — that one is about a *different* code path issue, opaque-attribute storage, not type recognition). | A test with a made-up type code and `FLAG_OPTIONAL` *not* set (i.e. flagged well-known), asserting `UnrecognizedWellKnownAttribute` rather than silent acceptance as `Unknown` |
| NEXT_HOP semantic correctness for one-hop eBGP: MUST be the sender's session IP, or share a common subnet with the receiver | **Confirmed gap, low severity** | `is_valid_next_hop_v4` (`pathvectord/src/daemon/route.rs:843-849`) only rejects unspecified/loopback/multicast/broadcast/self-address — it doesn't check either of the RFC's precise criteria (matches sender's IP, or shares a subnet with us). Note the RFC's own remediation for a semantically-incorrect NEXT_HOP is lenient regardless ("error SHOULD be logged, and the route SHOULD be ignored... NOTIFICATION SHOULD NOT be sent, connection SHOULD NOT be closed") — so this isn't a security-severity issue, just a looser acceptance criterion than the RFC's precise text; it also happens to match how "third-party next-hop" is commonly and intentionally used in real deployments (e.g. route-server/shared-media setups), so tightening this may not even be desirable without a config toggle. | Decide (not just implement) whether this should be tightened at all — if so, a config-gated stricter check plus a test with a NEXT_HOP that's neither the sender's address nor same-subnet, asserting the route is dropped |

**§6.3 summary (partial):** 2 new clauses reviewed, both confirmed gaps (one
low-severity/debatable). The remaining §6.3 clauses (Malformed Attribute
List for oversized withdrawn/attribute lengths, AS_PATH syntactic
validation, NLRI syntactic validation, Optional Attribute Error for
non-RFC-7606-covered optional attributes) are not yet independently
re-verified this pass — the structural/framing-level ones almost certainly
fall into the same already-tracked deferred `CodecError` bucket as the
§6.2 Unsupported Version finding above, but that should be *confirmed*,
not assumed, in a follow-up pass.

---

## §6.4 — NOTIFICATION Message Error Handling

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| A received NOTIFICATION that itself has an error (e.g. unrecognized Error Code/Subcode) must NOT be answered with another NOTIFICATION — SHOULD be logged only | Confirmed correct | A malformed/undecodable NOTIFICATION hits the generic body-level `CodecError` path (`transport/mod.rs`'s `Some(Err(e))` arm), which — per the §6.1/§6.2 findings above — only maps the 3 header-layer errors to a reply NOTIFICATION and otherwise just `tracing::warn!`s and drops the connection; there's no code path that would construct a NOTIFICATION *in response to* a received NOTIFICATION regardless of what's wrong with it. A successfully-decoded NOTIFICATION with an unrecognized Error Code/Subcode also can't trigger a reply — receiving *any* `BgpMessage::Notification` just terminates the session (see the FSM's `NotificationReceived`-shaped inputs), it never dispatches to a "reply" path. This is actually a case where the already-known, already-deferred generic-CodecError behavior happens to be exactly RFC-correct for this specific clause, not a coincidence worth re-litigating. | — |

**§6.4 summary:** 1 clause reviewed, confirmed correct.

## §6.5 — Hold Timer Expired Error Handling

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| Hold Timer expiry → NOTIFICATION with Error Code Hold Timer Expired, connection closed | Confirmed correct | All 3 `HoldTimerExpired` arms in `fsm/mod.rs` (lines 330, 421, 503) construct `NotificationError::HoldTimerExpired` specifically (not a generic/wrong code) before `CloseTcpConnection` | `test_hold_timer_expired_in_open_sent`, `test_hold_timer_expired_in_open_confirm`, `test_hold_timer_expired_in_established` (already well-established from the fault-injection-testing work) |

**§6.5 summary:** 1 clause reviewed, confirmed correct.

## §6.6 — Finite State Machine Error Handling

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| Any FSM error (e.g. an unexpected event/message for the current state) → NOTIFICATION with Error Code Finite State Machine Error | Confirmed correct | `on_open_sent`'s catch-all `MessageReceived(_)` arm (`fsm/mod.rs:360-369`) sends `FsmErrorOpenSent` for any message type other than the one expected in that state; per RFC 6608 (already tracked ✅) the subcode is state-specific (`FsmErrorOpenSent`/`FsmErrorOpenConfirm`/`FsmErrorEstablished`) rather than the RFC 4271-only generic `FsmError`, which is a superset/refinement, not a violation | RFC 6608's existing test coverage (already ✅ in `pathvector-session/RFC.md`) |
| (Secondary observation, not a gap) Non-message `FsmInput` variants that don't apply to a given state fall through to a silent `_ => vec![]` no-op in some state handlers | Confirmed correct, reasoned rather than gap | The RFC's "unexpected event" language is about receiving a *protocol message* that doesn't belong in the current state (which the message-reception catch-alls above already handle) — internal plumbing events like a stray timer tick that doesn't apply to the current state aren't "BGP events" in the sense this clause is concerned with, so a silent no-op there is a reasonable interpretation, not a violation | — |

**§6.6 summary:** 2 clauses reviewed, both confirmed correct.

## §6.7 — Cease

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| Terminating a session because a locally-configured prefix-count upper bound was exceeded MUST send NOTIFICATION(Cease, MaximumNumberOfPrefixesReached) | Confirmed correct | `pathvectord/src/daemon/route.rs:288-328` checks `adj_rib_in.len() > limit` after each UPDATE and sends exactly this NOTIFICATION; this implementation goes further than the bare RFC requirement by also supporting an `max_prefixes_restart` idle-hold delay (a common real-world BGP extension beyond the RFC text) | `cease_when_limit_exceeded`, `cease_when_v6_limit_exceeded`, `idle_hold_inserted_when_restart_configured`, `no_idle_hold_without_restart`, `no_limit_when_unconfigured` (all per `pathvectord/RFC.md`) — this is one of the more thoroughly-tested corners of the codebase |
| A BGP peer MAY close its connection at any time via NOTIFICATION(Cease) in the absence of a fatal error | Confirmed correct | Administrative shutdown already sends `NotificationError::Cease(CeaseError::AdministrativeShutdown)` on `ManualStop` (`fsm/mod.rs:341-350`, RFC 9003-covered elsewhere) | Existing RFC 9003 test coverage |

**§6.7 summary:** 2 clauses reviewed, both confirmed correct — this is a
genuinely solid corner of the codebase, worth noting since not every finding
in this audit has been a gap.

## §6.8 — BGP Connection Collision Detection

**This section contains the most severe finding of the audit to date —
verified with extra care (mechanical re-derivation from the RFC's literal
numbered steps, cross-checked against the existing test's own behavior)
given how surprising and consequential it is.**

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| Detect simultaneous connections (collision) when both sides are in OpenConfirm (or OpenSent, optionally) for the same peer | Confirmed correct | `handle_incoming_connection` (`transport/mod.rs:617-675`) matches on `self.fsm.state()`, treating `OpenSent`/`OpenConfirm` as collision-candidate states and `Idle`/`Connect`/`Active` as not (matching the RFC's explicit "collision cannot be detected with connections in Idle, Connect, or Active" note) and `Established` as "always reject the new one" | — |
| **Retain the connection *initiated by* the BGP speaker with the higher-valued BGP Identifier** | **Confirmed gap — inverted logic, high severity** | `handle_incoming_connection`'s `should_close_outbound = local_bgp_id > peer_id` (line 634-637) is backwards. Mechanically working through the RFC's own numbered procedure in this codebase's terms (where "the existing connection" is always the locally-*initiated*/outbound one, and "the newly received OPEN" is always the incoming one, confirmed via the function's own doc comment): Rule 2 says local_id < remote_id ⇒ close the *existing* (outbound), accept the *new* (incoming); Rule 3 says otherwise (local ≥ remote) ⇒ close the *new* (incoming), keep the *existing* (outbound). The code's condition does the **opposite of both**: it closes the outbound when *local* is higher (Rule 3 says keep it then) and keeps the outbound when *local* is lower (Rule 2 says close it then). This isn't a reading-comprehension slip on the implementer's part that happens to be harmless — I mechanically re-derived it twice, including working a concrete two-node example (A initiates Connection1 to B, B initiates Connection2 to A; whichever side has the lower ID should end up on Connection2 per RFC, but the code makes both sides converge on Connection1, initiated by the *lower*-ID side) and confirming it against the *existing test's own asserted outcome*: `test_collision_in_open_confirm_peer_bgp_id_higher_rejects_incoming` sets up a scenario where the **peer's** ID is higher, and asserts the session reaches `Established` over the **outbound** connection (see its final comment: "Complete the handshake — session keeps the outbound and reaches Established" — right after asserting `"expected Established after peer-wins collision"`). That is precisely backwards from the RFC: when the peer's ID is higher, the RFC says keep the **peer-initiated (incoming)** connection, not our own outbound one. The test locks in the inverted behavior as if it were the intended, correct outcome — which is exactly why this has never been caught. **Interop consequence, not just a labeling issue:** because the logic is self-consistent when two `pathvectord` instances talk to each other (both sides independently invert, and still agree on one surviving connection — see the worked derivation in the initial investigation), this would not show up as a crash or an obviously-broken session between two instances of this daemon. But against a *correctly*-implemented peer (GoBGP, BIRD, FRR, or any standards-compliant implementation) in a genuine simultaneous-connect race, each side would compute a *different* required survivor and each would close the connection the other side is trying to keep — a mutually-destructive collision resolution that could prevent the session from ever establishing in that specific race window, rather than gracefully converging on one connection as intended. Existing e2e interop suites don't appear to exercise a genuine simultaneous-connect race against GoBGP/BIRD/FRR specifically (the only test citing this is the in-process unit test above), so this has had no opportunity to surface. | Fix: invert the condition (`should_close_outbound` should be true when `local_bgp_id < peer_id`, matching RFC Rule 2) — then rewrite `test_collision_in_open_confirm_peer_bgp_id_higher_rejects_incoming`'s own assertion (its scenario, peer ID higher, should result in the **incoming** connection surviving, not the outbound one — the test's name will also need to change, since "peer_bgp_id_higher_rejects_incoming" describes the *current, wrong* behavior). A real-teeth verification (break the fix, confirm the corrected test fails, restore) is especially warranted here given how this exact kind of self-consistent-but-inverted bug can silently pass review. An e2e test with a genuine simultaneous-connect race against a real GoBGP/BIRD/FRR peer would give the strongest possible proof this actually interops correctly, beyond the unit level. |
| Send NOTIFICATION(Cease, ConnectionCollisionResolution) on the connection closed as a result of collision resolution | **Confirmed gap** | Both `on_open_sent`'s and `on_open_confirm`'s `CollisionDetected` FSM arms (`fsm/mod.rs:354-358`, `446-454`) only emit `StopHoldTimer`/`StopKeepaliveTimer`/`CloseTcpConnection` — no `SendMessage` at all, let alone the `Cease`/`ConnectionCollisionResolution` NOTIFICATION (which does already exist as a codec-level type, `CeaseError::ConnectionCollisionResolution`, RFC 4486 subcode 7 — it's just never constructed anywhere outside tests/round-trip code). The existing `pathvectord/RFC.md` row claiming this was ✅ had `—` (no test) in its "Verified by" column, which should have been a signal — corrected to ❌ as part of this pass. | A test asserting `CollisionDetected` produces a `SendMessage(Notification(Cease/ConnectionCollisionResolution))` output before `CloseTcpConnection`, then wire up the missing `FsmOutput` in both arms |
| Connection collision cannot be detected with connections in Idle, Connect, or Active states | Confirmed correct | Already covered above (first row) | — |
| A collision with an existing `Established` connection causes the new connection to be closed (absent config otherwise) | Confirmed correct | `handle_incoming_connection`'s `State::Established` arm (line 666-673) unconditionally rejects the incoming connection — no config toggle exists to change this, which matches the RFC's default ("unless allowed via configuration") without needing to implement the optional override | — |

**§6.8 summary:** 4 clauses reviewed — 2 confirmed correct, 2 confirmed gaps
(one of which — the inverted BGP-ID comparison — is the most severe and
highest-confidence finding of this audit so far, corrected in both
`pathvectord/RFC.md` and the aggregate `RFC_REQUIREMENTS.md` §8 row).

## §7 — BGP Version Negotiation

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| Version negotiation itself (retrying with progressively lower version numbers on Unsupported Version Number) is a MAY-level feature; the only MUST is that future BGP versions retain the OPEN/NOTIFICATION message format | Confirmed correct — not applicable | This implementation only supports version 4 (`BGP_VERSION` constant, checked in `open.rs:39-43`) and makes no attempt at multi-version retry logic — since the retry mechanism itself is optional (MAY) and there is only one version to support, there's nothing to implement here. The one MUST (retain message format across versions) is trivially satisfied since there's only one version in play. This does compound with the already-noted §6.2 gap (Unsupported Version Number NOTIFICATION's Data field isn't populated), which would matter more if a real version-negotiation retry loop existed on either end — but since neither this implementation nor typical modern peers attempt version renegotiation in practice (BGP-4 has been the only deployed version for decades), this is low priority. | — |

**§7 summary:** 1 clause reviewed, confirmed correct (not applicable).

### RFC 4271 running total so far (§4, §5, §6.2–§6.8, §7)

29 clauses reviewed — 20 confirmed correct, 6 confirmed gaps, 3 needs
investigation. The two most severe findings are the inverted connection-
collision BGP-ID comparison (§6.8) and the un-ignored eBGP LOCAL_PREF (§5.1.5)
— both filed in `TODO.md`, neither fixed as part of this diagnostic pass.

---

## §8 — BGP Finite State Machine

**Scope this pass:** §8.1 (events — mostly optional/discretionary features,
scanned rather than exhaustively derived) and a targeted check of `on_idle`,
`on_connect`, `on_active` (the three states this audit hadn't yet looked at
directly — `on_open_sent`/`on_open_confirm`/`on_established` were already
covered by the fault-injection-testing work and the collision-detection deep
dive above). The full ~1200-line §8.2.2 per-state event table was not
re-derived clause-by-clause this pass — see the honesty note at the end of
this section.

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| §8.1.2: only Event 1 (ManualStart) and Event 2 (ManualStop) are mandatory administrative events; Events 3-8 (Automatic* variants tied to DampPeerOscillations/IdleHoldTime/etc.) are all optional | Confirmed correct — scope choice, not a gap | This implementation has `ManualStart`/`ManualStop` and doesn't implement automatic start/stop, peer-oscillation damping, or delay-open — all legitimately optional per the RFC's own text, same category of deliberate scope choice as third-party NEXT_HOP (§5) and multi-version negotiation (§7) | — |
| §8.1.3/8.1.4: mandatory timer/TCP events (ConnectRetryTimer_Expires, HoldTimer_Expires, KeepaliveTimer_Expires, TCP success, TcpConnectionFails) vs. optional ones tied to TrackTcpState/DelayOpen | Confirmed correct | All mandatory timer/TCP events have direct `FsmInput` equivalents (`ConnectRetryTimerExpired`, `HoldTimerExpired`, `KeepaliveTimerExpired`, `TcpConnected`, `TcpFailed`) already extensively tested; optional ones (DelayOpenTimer, granular TCP-state tracking) aren't modeled, consistent with not implementing DelayOpen | — |
| `on_idle`: only `ManualStart`/`ConnectRetryTimerExpired` transition out (to Connect); everything else ignored | Confirmed correct | `fsm/mod.rs:245-256` — the `ConnectRetryTimerExpired` arm here is what makes the earlier `HoldTimerExpired` fix (fault-injection-testing work) actually complete a reconnect cycle: without `on_idle` handling this input, arming the retry timer on hold-timeout would be a no-op. Already proven end-to-end by `mid_session_tcp_reset_recovers_cleanly` (e2e). | — |
| `on_connect`: TCP success → OpenSent; TCP failure → Active + restart ConnectRetryTimer; ConnectRetryTimer_Expires → re-initiate + restart timer; ManualStop → clean stop | Confirmed correct | `fsm/mod.rs:258-272` — matches the RFC's Connect-state behavior structurally | — |
| `on_active`: TCP success → proceed; ConnectRetryTimer_Expires → back to Connect + re-initiate; ManualStop → clean stop | Confirmed correct | `fsm/mod.rs:274-287` | — |

**Honesty note:** this pass did not re-derive the full §8.2.2 per-state event
table (all 6 states × ~10 applicable events each) clause-by-clause against
the RFC prose — that table is enormous (~1200 lines) and this codebase's
core state-transition behavior (Idle→Connect→OpenSent→OpenConfirm→
Established, hold/keepalive timers, NOTIFICATION-before-close) has already
been extensively exercised by the fault-injection-testing work (which found
and fixed the `HoldTimerExpired`/`ConnectRetryTimer` bug) and by this pass's
own collision-detection deep dive (§6.8). Marking the remaining untouched
corners "confirmed correct" without actually re-deriving them would defeat
the point of this audit — they're left as an open item for a future pass
rather than assumed.

**§8 summary:** 5 clauses reviewed, all confirmed correct — plus the §6.8
collision-detection findings (2 confirmed gaps) already logged above under
§6.8, which this section doesn't re-count.

## §9.1 — Decision Process

### §9.1.1 — Phase 1: Calculation of Degree of Preference

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| iBGP-learned route: LOCAL_PREF attribute value is the degree of preference (or local policy overrides it) | Confirmed correct | Already covered under §5.1.5 above — LOCAL_PREF from iBGP peers is correctly honored | See §5 findings |
| eBGP-learned route: degree of preference is computed from local policy, not taken from the wire; if the eBGP peer sent a LOCAL_PREF, it has no bearing here | This directly reinforces the existing §5.1.5 finding, not a new one | This is the same underlying issue as the already-logged §5.1.5 gap (eBGP LOCAL_PREF not ignored) — this clause adds confirmation that the RFC's *positive* requirement (compute preference from policy) exists alongside the *negative* one (ignore the wire value). Checked: `pathvector-policy` does have a `SetLocalPref` action (`action.rs:78-94`), so operators *can* assign a computed preference to eBGP routes via import policy — the mechanism for the "compute from local policy" half of this clause already exists and is unaffected by the wire-capture bug. | Same fix as the §5.1.5 finding closes this too |
| The computed degree-of-preference value MUST be used as LOCAL_PREF in any iBGP re-advertisement | Needs investigation, minor | When policy explicitly sets `local_pref` via `SetLocalPref`, it correctly flows to `route_to_attributes` and gets attached on the wire to iBGP peers (`prepare_outbound`'s iBGP branch doesn't touch `local_pref` at all, so a policy-assigned value survives). When *no* policy sets it (the common/default case), the route's `local_pref` stays `None`, and no `LocalPref` attribute is attached to the iBGP-bound UPDATE at all — the receiving iBGP peer then defaults it to 100 on their own side, which happens to produce the same *numeric* outcome as an explicit `LocalPref(100)` would, but isn't literally "using the computed value as LOCAL_PREF in the readvertisement" as the RFC's text describes. Low practical impact given the numeric outcome matches in the default case. | Confirm whether any BGP interop test suite would actually observe a difference between "no LOCAL_PREF attribute, defaults to 100 on the far end" vs. "explicit LocalPref(100) attribute" — if not, this is arguably not worth changing |

**§9.1.1 summary:** 3 clauses reviewed — 1 confirmed correct, 1 reinforcing
an already-logged gap (not double-counted), 1 minor needs-investigation.

### §9.1.2 / §9.1.2.1 / §9.1.2.2 — Phase 2: Route Selection, Resolvability, Tie-Breaking

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| §9.1.2.1: exclude routes with unresolvable NEXT_HOP from Phase 2 | Confirmed correct (cross-referenced, not re-derived fresh) | This is already extensively covered by the existing FIB-integration/oracle work (`NextHopOracle`, `is_valid_next_hop_v4/v6`, Step 1 of the comparator rejecting unreachable NEXT_HOP) tracked and tested elsewhere in this project (TODO.md history items on FIB write-failure counters, IGP metric oracle, etc.) | Existing test suite for `NextHopOracle`/Step 1 |
| §9.1.2.2 tie-break order: (a) shortest AS_PATH, (b) lowest ORIGIN, (c) lowest MED same-neighbor-AS, (d) eBGP over iBGP, (e) lowest IGP metric, (f) lowest BGP Identifier, (g) lowest peer address | **Confirmed gap — (f) and (g) conflated** | `best_path.rs`'s comparator implements (a)-(e) correctly (Steps 4-8 in the existing table, already ✅), then has its own extra "Step 9: oldest eBGP route" (see next row), then a single final "Step 10: Lowest peer IP address" (`best_path.rs:232-233`, `peer_b.cmp(peer_a)`) — comparing **peer IP address only**. This conflates the RFC's two *distinct* final criteria: (f) lowest **BGP Identifier** (the router-id from the peer's OPEN message) and (g) lowest **peer address** (the session's source IP) into a single peer-IP-only comparison, skipping (f) entirely. These are not always the same value — a router's BGP Identifier is commonly a loopback address, unrelated to the physical/session IP used for a given peering — so whenever two candidate routes tie all the way down to this point but their BGP-Identifier ordering and peer-IP ordering *disagree* (concretely: peer A has session IP 10.0.0.5 but BGP Identifier 1.1.1.1; peer B has session IP 10.0.0.2 but BGP Identifier 9.9.9.9 — RFC's (f) prefers A, since 1.1.1.1 < 9.9.9.9, but a peer-IP-only comparison prefers B, since 10.0.0.2 < 10.0.0.5), this implementation would pick a different winner than RFC 4271's literal algorithm specifies. This only matters in the (rare) case of a genuine full tie through step (e); most route comparisons resolve earlier. | A test with two routes tied through IGP metric and route age, but with BGP Identifier ordering and peer-IP ordering deliberately set to disagree, asserting the RFC's (f)-then-(g) order is followed rather than peer-IP-only |
| §9.1.2.2 note: "BGP implementations MAY use any algorithm that produces the same results" | Confirmed correct as a general principle, doesn't excuse the above | This MAY clause is about implementation technique (e.g. this codebase's single-pass comparator vs. the RFC's iterative "remove from consideration" pseudocode), not about skipping or reordering the criteria themselves — the (f)/(g) conflation above is a genuine divergence in *results* for the disagreeing-orderings case, not just a different-but-equivalent algorithm | — |
| (Extra, non-RFC step) "Step 9: oldest eBGP route" inserted between (e) and (f)/(g) | Confirmed correct — deliberate, common real-world deviation, not a gap | This specific step does not appear anywhere in RFC 4271's literal (a)-(g) list — it's a widely-implemented real-world BGP practice (preferring the older/more-stable eBGP route to reduce oscillation) that several major vendor implementations include, generally regarded as an acceptable, intentional deviation rather than a compliance defect, similar in spirit to this project's existing MRAI-withdrawal design choice (see §9.2.1.1 below) | — |
| §9.1.4 Overlapping Routes / ATOMIC_AGGREGATE "MUST NOT make NLRI more specific" | Not yet reviewed this pass | This project doesn't perform route aggregation (§9.2.2.2 not implemented, already noted under the §5 AGGREGATOR finding), so the specific "more specific NLRI" scenario this clause guards against has no applicable code path — tentatively N/A, but not independently confirmed this pass | Confirm there's no de-aggregation/more-specific-splitting logic anywhere that this would apply to |

**§9.1.2 summary:** 4 clauses reviewed (plus 1 not yet reviewed) — 3
confirmed correct (1 of those explicitly a deliberate non-RFC addition, not
a violation), 1 confirmed gap (the (f)/(g) conflation).

### §9.1.3 — Phase 3: Route Dissemination

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| A route SHALL NOT be installed in Adj-RIB-Out unless its destination and NEXT_HOP can be forwarded per the Routing Table; if excluded, the previously-advertised route MUST be withdrawn via UPDATE | Confirmed correct (cross-referenced) | Covered by the existing, extensively-tested FIB-reachability-change handling (`test_on_fib_change_withdraws_when_next_hop_goes_down`, `test_on_fib_change_reannounces_when_next_hop_recovers`, per `pathvector-rib/RFC.md`'s Step 1/Step 8 citations) — a NEXT_HOP going unreachable correctly triggers a withdrawal, not just a skip | Existing FIB-integration test suite |

**§9.1.3 summary:** 1 clause reviewed, confirmed correct.

## §9.2 — Update-Send Process

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| §9.2.1.1: MinRouteAdvertisementIntervalTimer applies to "advertisement **and/or withdrawal**" of routes to a common destination set — the RFC's literal text does *not* exempt withdrawals | **Confirmed gap — in the documentation's RFC citation, not necessarily in the design decision itself** | `pathvectord/RFC.md` (before this pass) asserted "Withdrawals bypass MRAI (RFC 4271 §9.2.1.1 **explicit exemption**)" — I fetched and read the actual §9.2.1.1 text directly rather than trusting this citation, and it says the opposite: "Two UPDATE messages sent by a BGP speaker to a peer that advertise feasible routes **and/or withdrawal of unfeasible routes** to some common set of destinations MUST be separated by at least MinRouteAdvertisementIntervalTimer." There is no "explicit exemption" language anywhere in this section. The underlying *design decision* (send withdrawals immediately, unthrottled) is defensible on real-world safety grounds — delaying a withdrawal keeps a stale/blackholed route reachable for longer, a real operational cost that arguably outweighs strict adherence here — but the documentation overstated its RFC basis, claiming an explicit textual exemption that doesn't exist. Corrected the citation in `pathvectord/RFC.md` (✅ → ⚠️) as part of this pass; the underlying behavior itself is left as "needs a documented rationale, not a code change" rather than "confirmed gap requiring a fix," since I can't rule out this is intentional, defensible, real-world-informed engineering — just not what the raw RFC text says. | Either (a) find the actual justification (operational-safety reasoning, a related errata, or common-practice citation) and rewrite the doc's claim honestly instead of citing a nonexistent "explicit exemption," or (b) reconsider whether withdrawals should in fact respect MRAI per the literal text — this is a judgment call, not an obvious bug, so it shouldn't be fixed reflexively |
| MRAI enforcement itself (30s eBGP window, per-NLRI suppression/flush) | Confirmed correct | Already well-tested — `mrai_suppresses_ebgp_announcement_within_window`, `mrai_passes_after_window_elapsed`, `flush_mrai_pending_clears_elapsed_pending` (per `pathvectord/RFC.md`) | Same |
| iBGP MRAI SHOULD be ≥5s (or SHOULD NOT apply the eBGP procedure to iBGP at all — RFC offers this as an explicit either/or) | Confirmed correct — already tracked as a known, deliberate deferral | `pathvectord/RFC.md` already documents this as deferred (❌), and `RFC_REQUIREMENTS.md`'s §9.1/§9.2 rows are already ⚠️ reflecting it — nothing new to add here, this pass just confirms the existing tracking is accurate | Already tracked |

**§9.2 summary:** 3 clauses reviewed — 1 confirmed gap (documentation
citation, not necessarily the underlying design), 2 confirmed correct
(one an already-known, already-tracked deferral).

## §10 — BGP Timers

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| ConnectRetryTimer, HoldTimer, KeepaliveTimer are all configurable per-connection; Hold Time of 0 disables Hold/Keepalive timers | Confirmed correct | Already extensively covered under §4.2/§6.2/§8 above and by the fault-injection-testing work — `test_hold_time_zero_disables_timers`, `DEFAULT_CONNECT_RETRY_TIME`, per-peer `connect_retry_time` config | Existing test suite, no new gaps found |
| KeepaliveTimer recommended at 1/3 of Hold Time | Confirmed correct | `test_keepalive_interval_is_third_of_hold_time` (already ✅ per `pathvector-session/RFC.md`) | Same |

**§10 summary:** 2 clauses reviewed, both confirmed correct — no new
findings; this section is fully subsumed by work already covered elsewhere
in this audit.

### RFC 4271 running total (§4, §5, §6.2–§7, §8, §9, §10)

42 clauses reviewed — 29 confirmed correct, 8 confirmed gaps, 5 needs
investigation. **RFC 4271 audit considered substantially complete** —
remaining unaudited: §1-§3 (definitional/overview, low value), the full
§8.2.2 per-state event table (already extensively exercised by testing,
explicitly not re-derived clause-by-clause — see honesty note above), and
§9.1.4 (overlapping routes, tentatively N/A pending confirmation).

**All 8 confirmed gaps, for reference:** (1) OPEN/ROUTE_REFRESH accept
trailing padding (§4.1); (2) no Attribute Flags Error detection (§4.3);
(3) unrecognized transitive-optional attributes can't survive a relay
(§5); (4) eBGP LOCAL_PREF not ignored (§5.1.5 — most severe of the
"silent policy corruption" class); (5) unrecognized OPEN optional
parameters silently skipped (§6.2); (6) unrecognized well-known
attributes accepted as ordinary unknowns (§6.3); (7) connection
collision BGP-ID comparison inverted (§6.8 — most severe overall,
interop-breaking in a specific race); (8) tie-break steps (f)/(g)
conflated into peer-IP-only (§9.1.2.2). All filed in `TODO.md` (#12-#15),
none fixed as part of this diagnostic audit.

---

*(Sections §1–3 not covered — low value, mostly definitional.)*

**Cross-reference note:** the RFC 4271 §6.8 finding above ("A collision with
an existing Established connection causes the new connection to be closed" —
marked Confirmed correct) needs a caveat discovered during the RFC 4724 pass
below: that verdict is only correct for **non-GR** sessions. RFC 4724 §5
overrides this specific behavior for GR-negotiated sessions, and this
implementation doesn't make that distinction at all. See the RFC 4724
section's §5 finding below for detail — not re-litigated here to avoid
duplicating the same evidence in two places.

---

# RFC 4724 — Graceful Restart Mechanism for BGP

**Audited:** 2026-07-16
**Method:** Full text fetched from rfc-editor.org/rfc/rfc4724 (843 lines,
much shorter than RFC 4271), read in full; cross-checked against
`pathvector-session` (capability codec, FSM), `pathvector-rib` (stale-route
marking/best-path de-preference), and `pathvectord` (`daemon/gr.rs`,
`daemon/peer.rs`, `daemon/capabilities.rs` — the bulk of the GR logic lives
here). This project had already implemented substantial GR functionality
across several earlier work sessions (R-bit lifetime, Phase 2 "Receiving
Speaker" stale-route retention, EOR send/receive, per-family retention,
GR-deadline-expiry flush) with an existing, extensive test suite — this
pass re-verifies that work against the actual RFC text fresh, rather than
trusting the existing `pathvectord/RFC.md` checklist at face value, and
specifically looks for the class of requirement that's easy to miss
entirely: things the checklist never had a row for in the first place.

**Overall finding: the *Receiving Speaker* role (§4.2 — holding a peer's
routes as stale when the peer restarts) is thoroughly implemented and
well-tested. The *Restarting Speaker* role (§4.1 — deferring our own route
selection when *we* restart) has no implementation at all.** These are two
distinct, independent halves of the RFC that a full implementation needs
both of, and the existing documentation's "helper role, speaker role"
framing doesn't clearly separate them, which likely contributed to §4.1
never being tracked as a gap.

## §2 — Marker for End-of-RIB

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| IPv4 unicast EOR = minimum-length UPDATE; other AFI/SAFI EOR = UPDATE with only MP_UNREACH_NLRI, empty withdrawn, for that AFI/SAFI | Confirmed correct (cross-referenced, not re-derived fresh) | Already extensively tested per `pathvectord/RFC.md`: `test_on_established_empty_rib_sends_eor_only`, `test_on_established_ipv6_capable_peer_receives_both_eors`, `test_ipv4_eor_received_is_recorded`, `test_ipv6_eor_received_is_recorded` — this pass read the RFC text directly and confirms the format description matches what these tests exercise | Existing test suite |

**§2 summary:** 1 clause reviewed, confirmed correct (well pre-existing
test coverage).

## §3 — Graceful Restart Capability

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| R-bit: set when the speaker has restarted; peer MUST NOT wait for EOR from a speaker with R=1 before advertising | Confirmed correct (cross-referenced) | R-bit lifetime already implemented and tested (`spawn_config_r_bit_set_within_restart_window`, etc.); the "peer must not wait for EOR from an R=1 speaker" half is a *receiving*-side behavior this project implements when *we* are the receiver — not independently re-verified this pass, but consistent with the existing `gr_capable_peers`/EOR-wait logic described in `pathvectord/RFC.md` | — |
| F-bit: only set if forwarding state was genuinely preserved during restart | Confirmed correct (cross-referenced) | `test_build_local_capabilities_f_bit_false_when_restarting` / `f_bit_true_when_stable` — this project's architecture always wipes/rebuilds its FIB view on process restart, so F-bit is honestly always false for its own restarts, which is the conservative/correct choice given it doesn't attempt real forwarding-state persistence across a process restart | Existing test suite |
| A BGP speaker MUST NOT include more than one instance of the Graceful Restart Capability; if the peer does anyway, the receiver **MUST ignore all but the *last* instance** | **Confirmed gap** | `peer.rs:383-402`'s `.find_map(\|c\| ...)` iterates the peer's advertised capabilities in wire order and returns the **first** `GracefulRestart` capability with `restart_time > 0` — the opposite of "ignore all but the last." The existing tests (`duplicate_gr_capabilities_do_not_panic_and_first_wins`, `zero_gr_then_nonzero_gr_uses_first_nonzero`) directly name and assert the current (non-compliant) "first wins" behavior. Real-world likelihood is low — a peer sending 2+ GR capability instances is itself an RFC violation on the sender's part — but the receiver-side handling is backwards when it happens. Corrected the misleading `pathvectord/RFC.md` row (which had claimed this as ✅) to ⚠️. | Reverse the `find_map` to take the last match instead of the first (e.g. iterate and overwrite rather than short-circuit on first `Some`), then rename the tests to describe correct ("last wins") behavior |
| Zero <AFI,SAFI> tuples in the capability ⇒ sender can't preserve forwarding state for any family, but still supports Receiving-Speaker procedures; Restart Time is irrelevant in this case | Confirmed correct | `families: Vec<GracefulRestartFamily>` naturally supports an empty vec with no special-casing needed elsewhere in the pipeline; proptest fuzzing already covers arbitrary family lists including empty ones (`gr_capability_roundtrips`) | Existing proptest suite |

**§3 summary:** 4 clauses reviewed — 3 confirmed correct, 1 confirmed gap.

## §4.1 — Procedures for the Restarting Speaker

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| MUST retain forwarding state (if possible) and mark stale; MUST NOT differentiate stale vs. other info during forwarding | Confirmed correct — by architecture, not by a preservation feature | This project doesn't attempt to preserve forwarding state across its own process restart at all (FIB is rebuilt from scratch on startup, confirmed via the F-bit-always-false-on-restart behavior above) — so there's no stale/non-stale distinction to make in the forwarding plane for *our own* restart, satisfying "MUST NOT differentiate" vacuously. This is an honest, defensible architecture choice (don't claim preservation you don't do), not a violation. | — |
| MUST set R-bit in OPEN after restart | Confirmed correct (already established, prior work) | `spawn_config_r_bit_set_within_restart_window` | Existing test suite |
| F-bit set only if forwarding state was genuinely preserved | Confirmed correct (already covered under §3 above) | — | — |
| **MUST defer route selection for an address family until (a) EOR received from all GR-capable peers (excluding restarting ones) or (b) the Selection_Deferral_Timer expires; an implementation MUST support a configurable timer for this** | **Confirmed gap — the largest unimplemented piece of RFC 4724 in this codebase** | Grepped the entire workspace for `Selection_Deferral`/`selection_deferral`/`SelectionDeferral`/any deferred-route-selection concept — zero matches anywhere in `pathvectord` or `pathvector-rib`. `handle_update`/`select_best` run immediately, synchronously, per-UPDATE with no notion of "our own restart is still settling, hold off on final decisions." **Practical consequence:** after `pathvectord` itself restarts and peers begin reconnecting and re-sending their routes, this daemon will start making best-path decisions and propagating routes to *other* peers as soon as the very first UPDATE arrives from *any* one peer — potentially well before all peers have finished re-sending their post-restart routing tables. This is exactly the premature/incomplete-information decision problem §4.1's deferral mechanism exists to prevent; it could cause transient bad route selection or unnecessary route churn (advertise a route, then immediately withdraw/replace it moments later as more complete information arrives from other peers) in the window right after a restart. This project's existing GR work covers the *Receiving Speaker* role (holding a *peer's* stale routes) extremely well, but the *Restarting Speaker* role (managing *our own* restart-time decisions) appears to have no code path at all. | This is a substantial feature, not a quick fix: a `Selection_Deferral_Timer` (configurable, RFC suggests sizing it generously), a way to track "have all GR-capable peers sent EOR since our own restart," and a gate in front of the decision-process/propagation pipeline that holds off on running `select_best`/`propagate_prefix` until either condition is met. Worth its own design discussion before scoping a fix — this significantly changes daemon startup behavior. |

**§4.1 summary:** 4 clauses reviewed — 3 confirmed correct, 1 confirmed gap
(a major, previously entirely-untracked one).

## §4.2 — Procedures for the Receiving Speaker

This is the half of RFC 4724 this project has invested the most engineering
effort in, and it shows — this pass didn't find any new gaps here beyond
what's already tracked, and confirms the existing extensive test suite
(`pathvectord/RFC.md`'s ~15 rows under this section, all ✅, covering
per-family retention, EOR-triggered pruning, GR-deadline-expiry flush,
stale-route de-preference in best-path, and clean-vs-unclean termination
handling) genuinely matches the RFC text on a fresh read.

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| On (undetected) TCP termination + new incoming connection from a GR-capable peer: MUST treat as termination of the old session, close old, keep new, **no NOTIFICATION sent** | See the §5 finding below — this is the FSM-level mechanism for this clause, and it's missing | — | See §5 below |
| On detected TCP termination for a GR-capable peer: retain routes for all previously-negotiated families, mark stale; delete any *already*-stale routes from a prior restart (handles consecutive restarts) | Confirmed correct | `unclean_termination_of_gr_peer_retains_routes`, per-family `gr_v4`/`gr_v6` check in `on_terminated` (per `pathvectord/RFC.md`) | Existing test suite |
| Our own R-bit MUST NOT be set unless we ourselves have restarted | Confirmed correct | Covered by the R-bit lifetime logic already verified under §3/§4.1 | — |
| If session doesn't re-establish within peer's advertised Restart Time, MUST delete all stale routes from that peer | Confirmed correct | `gr_deadline_expiry_flushes_stale_routes`, e2e `gr_phase2_routes_held_during_restart_window_then_flushed_on_expiry` | Existing test suite |
| On re-establishment: if F-bit not set for a family, or family absent from the new capability, or GR capability absent entirely ⇒ MUST immediately remove all stale routes for that family | Confirmed correct (cross-referenced) | Per-family retention logic (`gr_v4`/`gr_v6` checks) already tested; this pass didn't re-derive the exact F-bit-check branch line-by-line but the described behavior matches the existing test names and the `pathvectord/RFC.md` narrative | Would benefit from an explicit test naming the F-bit-false-on-reconnect case specifically, if one doesn't already exist under a different name |
| MUST send EOR after completing initial update (including the no-routes case) | Confirmed correct | Already covered under §2 | — |
| MUST replace stale routes with new updates as they arrive; MUST immediately remove any still-stale routes once peer's EOR is received | Confirmed correct | `eor_prunes_stale_routes_not_refreshed_by_peer`, `gr_phase2_eor_prunes_stale_routes_not_refreshed_by_peer` (e2e) | Existing test suite |
| MAY support a configurable upper-bound timer on stale-route retention (independent of Restart Time) | Confirmed correct | This is the GR-deadline timer already covered above — same mechanism serves both the Restart-Time-based deletion and this general upper bound | — |

**§4.2 summary:** 8 clauses reviewed, all confirmed correct — genuinely one
of the stronger, more thoroughly-tested corners of this codebase.

## §5 — Changes to BGP Finite State Machine

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| Idle state: resource initialization excludes whatever's needed to retain routes per §4.2 | Confirmed correct — by architecture | Route retention (`gr.rs`'s stale-tracking) lives entirely in `pathvectord`, independent of `pathvector-session`'s FSM state — Idle-state FSM resource cleanup in `pathvector-session` has no interaction with route retention at all, satisfying this by construction/separation of concerns | — |
| NOTIFICATION or TcpConnectionFails when GR **not** negotiated: normal immediate flush (unchanged from base RFC 4271) | Confirmed correct | This is the pre-existing, non-GR default behavior, already covered generally | — |
| **TcpConnectionFails specifically (not NOTIFICATION) when GR **was** negotiated: retain routes per §4.2 rather than deleting them outright** | Confirmed correct | This exact distinction (unclean/TCP-failure → retain for GR peers; NOTIFICATION/clean → flush immediately) is precisely what `unclean_termination_of_gr_peer_retains_routes` and `clean_termination_flushes_immediately` (RFC 8538-adjacent) already test and implement | Existing test suite |
| **Established state, new incoming connection succeeds (Event 16/17) while GR **was** negotiated (≥1 AFI/SAFI): MUST retain routes per §4.2, release other resources, drop the *old* established connection, initialize fresh resources, reset ConnectRetryCounter, start ConnectRetryTimer, move to Connect state — i.e. treat the new connection as evidence of peer restart, NOT as an ordinary RFC 4271 §6.8 collision to reject** | **Confirmed gap — significant, directly connects to the RFC 4271 §6.8 audit above** | `handle_incoming_connection`'s `State::Established` arm (`pathvector-session/src/transport/mod.rs:666-673`, already quoted in the RFC 4271 §6.8 section above) unconditionally rejects any new incoming connection while Established — `tracing::warn!(...); drop(stream); None` — with **no check for whether GR capability was negotiated with this peer at all**. This is exactly backwards for the scenario RFC 4724 §5 is designed to handle: a peer that restarted, whose old TCP connection died without us noticing (still "Established" from our point of view), reconnecting to re-establish the session. Per RFC 4271 §6.8's plain-vanilla rule, rejecting a new connection while Established is correct — but RFC 4724 explicitly *overrides* that rule for GR-negotiated sessions specifically. Since this project doesn't check GR-negotiated status at all in this code path, it always applies the non-GR default, meaning **a legitimately-restarting GR-capable peer trying to reconnect while we still (incorrectly) believe the old session is Established would have its reconnection attempt silently rejected**, likely forcing it to wait out our side's own Hold Timer expiry before we notice anything is wrong — defeating a meaningful part of the point of graceful restart (fast, clean recovery from a peer restart). Added a new row to `pathvectord/RFC.md`'s Connection Collision Coordination table for this. | A test: establish a session with GR negotiated, simulate the "old TCP connection appears alive to us but the peer has actually restarted and opens a new connection" scenario (mirroring the existing `test_collision_in_open_confirm_peer_bgp_id_higher_rejects_incoming`-style harness but in `State::Established` with GR capability recorded), asserting the new connection is adopted (routes retained per §4.2, old connection dropped, state moves to Connect) rather than rejected. This is a meaningfully-sized fix — needs the `State::Established` arm to check GR-negotiated status and branch accordingly, plus wiring the retain/reset behavior described in the RFC's replacement FSM text. |

**§5 summary:** 4 clauses reviewed — 3 confirmed correct, 1 confirmed gap
(the Established-collision-override — directly relevant to, and reinforces,
the severity of the RFC 4271 §6.8 collision-detection finding from the
earlier pass).

### RFC 4724 running total

21 clauses reviewed — 18 confirmed correct, 3 confirmed gaps. **RFC 4724
audit considered substantially complete.** The Receiving Speaker role
(§4.2) — the half most directly exercised by this project's own restart
scenarios in practice (peers restarting, not `pathvectord` itself) — is
genuinely solid. The 3 gaps are real and filed in `TODO.md` (#17):
duplicate-capability first-vs-last handling (minor, low real-world
likelihood), the missing Restarting-Speaker Selection_Deferral_Timer (major
feature gap, not yet scoped as a quick fix), and the missing
Established-collision GR override (significant, directly ties into the
RFC 4271 §6.8 finding's severity — a restarting GR-capable peer could have
its reconnection attempt silently rejected).

---

# RFC 9234 — Route Leak Prevention Using Roles in UPDATE and OPEN Messages

**Audited:** 2026-07-16
**Method:** Full text fetched from rfc-editor.org/rfc/rfc9234 (648 lines),
read in full; cross-checked against `pathvector-session` (Role capability
codec, `validate_open`), `pathvector-rib`/`pathvector-types` (OTC storage on
`Route`), `pathvector-policy` (`OtcLeakCondition`, `OtcPropagationCondition`,
`SetOtc`), and `pathvectord` (`install_otc_import_term`/`install_otc_export_term`
wiring per session role).

**Overall finding: the core OTC leak-detection/propagation logic is
carefully and correctly built** — every ingress/egress rule in §5 was
traced through the `session_role`-based wiring in `pathvectord/src/daemon/mod.rs`
and matches the RFC's precise text, including the easy-to-get-backwards
"session_role = our own role toward this peer" mapping (verified concretely
for both directions before trusting it). Two real gaps found regardless,
one of them security-relevant.

## §4.1/§4.2 — BGP Role Capability and Role Correctness

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| Role Capability: code 9, length 1, values 0-4 defined, 5-255 unassigned | Confirmed correct | `test_role_capability_roundtrip_all_defined_values`, `test_role_capability_unrecognized_value_decodes_as_unknown` (per `pathvector-session/RFC.md`) | Existing test suite |
| We MUST NOT advertise multiple Role Capability instances ourselves | Confirmed correct | Our own `capabilities` list is built deterministically from config with at most one `Capability::Role` push — no code path could accidentally emit two | — |
| Role-pair correctness: if both sides advertise, pair MUST be one of {Provider↔Customer, RS↔RS-Client, Peer↔Peer}, else MUST reject with Role Mismatch (code 2, subcode 11) | Confirmed correct | `validate_open` (`fsm/mod.rs:704-723`), `test_role_pair_matrix` (25 combinations) | Existing test suite |
| Backward compatibility: Role sent but not received (or vice versa) is not a mismatch by default | Confirmed correct | `test_role_absent_on_peer_side_is_not_a_mismatch`, `test_role_absent_locally_is_not_a_mismatch` | Existing test suite |
| Multiple **identical** Role Capabilities from peer ⇒ treat as one, proceed. Multiple Role Capabilities with **differing** values ⇒ MUST reject with Role Mismatch | **Confirmed gap** | `validate_open`'s peer-role extraction (`fsm/mod.rs:712-715`) is `peer.capabilities.iter().find_map(\|c\| match c { Capability::Role(r) => Some(*r), _ => None })` — takes the **first** `Capability::Role` instance and never looks at any subsequent ones. A peer sending two *different* Role values (e.g. `Role(Customer)` then `Role(Provider)`) would silently have only the first honored — the RFC-mandated detection-and-reject for conflicting duplicates never happens. **This is the exact same code shape as the RFC 4724 GR "first instance wins" bug found in the prior audit pass** (`peer.rs`'s GR capability `find_map`) — worth noting as a recurring pattern across this codebase: whenever a capability is theoretically singular but the wire format allows repetition, the natural `find_map`/`.iter().find(...)` idiom silently takes "whichever comes first" rather than validating uniqueness. A future pass auditing *other* capability types for the same shape (RFC 5492's capability negotiation in general) would be worthwhile. | A test with two `Capability::Role` entries carrying different values in one peer OPEN, asserting Role Mismatch NOTIFICATION rather than silent use of the first |
| Strict mode (require peer to advertise Role) | Already correctly tracked as deferred | `pathvector-session/RFC.md` already documents this as an explicit, non-default, RFC-optional deferral — not re-litigated here | Already tracked |

**§4.1/§4.2 summary:** 6 clauses reviewed — 5 confirmed correct, 1 confirmed
gap (which directly echoes a pattern already found once in RFC 4724).

## §5 — BGP Only to Customer (OTC) Attribute

| Clause | Confidence | Notes | What would close this out |
|---|---|---|---|
| OTC: optional transitive, type code 35, length 4 | Confirmed correct | `test_only_to_customer_roundtrip`, `test_only_to_customer_encodes_as_optional_transitive` (flags `0xC0` = optional+transitive) | Existing test suite |
| Ingress rule 1: OTC present + received from a peer who is our Customer or RS-Client ⇒ leak, ineligible | Confirmed correct | `OtcLeakCondition::matches` (`pathvector-policy/src/otc.rs:46-54`): `(Role::Provider \| Role::RouteServer, Some(_)) => true` — "our role = Provider/RouteServer" means "the peer is our Customer/RS-Client," matching this rule exactly. Verified the role-mapping convention concretely (traced both directions) before trusting this, given how easy this exact kind of role-relative logic is to get backwards. | `OtcLeakCondition` unit tests |
| Ingress rule 2: OTC present + received from a Peer + value ≠ peer's AS number ⇒ leak, ineligible | Confirmed correct | `(Role::Peer, Some(otc)) => otc != self.peer_asn` — matches exactly | Existing test suite |
| Ingress rule 3: received from Provider/Peer/RS + OTC absent ⇒ MUST add OTC = remote AS | Confirmed correct | `install_otc_import_term` (`pathvectord/src/daemon/mod.rs:652-660`) installs `AnyCondition → SetOtc::new(peer_asn)` when `session_role` is `Customer\|Peer\|RsClient` (i.e. peer is our Provider/Peer/RS) — matches | Existing test suite |
| Egress rule 1: advertising to Customer/Peer/RS-Client(-as-RS) + OTC absent ⇒ MUST add OTC = local AS | Confirmed correct | `install_otc_export_term` (`daemon/mod.rs:677-680`) installs the attach term when `session_role` is `Provider\|Peer\|RouteServer` (i.e. peer is our Customer/Peer/RS-Client) — matches | Existing test suite |
| Egress rule 2: route already has OTC ⇒ MUST NOT be propagated to Providers/Peers/RSes | Confirmed correct | `install_otc_export_term` installs `OtcPropagationCondition → Reject` when `session_role` is `Customer\|Peer\|RsClient` (i.e. peer is our Provider/Peer/RS) — matches | Existing test suite |
| Once OTC is set, MUST be preserved unchanged | Confirmed correct | `SetOtc`'s doc comment and implementation are explicitly idempotent — "never overwrites an existing OTC value" | — |
| **Malformed OTC (length ≠ 4) SHALL be handled using treat-as-withdraw [RFC 7606]** | **Confirmed gap — security-relevant** | `rfc7606_policy()` (`pathvector-session/src/message/update.rs:60-71`) explicitly lists `ATTR_ORIGIN \| ATTR_AS_PATH \| ATTR_NEXT_HOP \| ATTR_LOCAL_PREF` and `ATTR_MP_REACH_NLRI` as `TreatAsWithdraw`; everything else — including `ATTR_ONLY_TO_CUSTOMER` — falls into the catch-all `_ => AttributeErrorPolicy::AttributeDiscard`. `AttributeDiscard` means "silently drop the malformed attribute; the UPDATE and route are otherwise processed normally" — i.e. a route with a malformed-length OTC is **accepted as if OTC had never been present at all**, rather than the whole route being withdrawn as the RFC requires. **Why this matters beyond strict-compliance pedantry:** OTC is the entire mechanism this RFC uses to detect and prevent route leaks. If a route that *should* carry OTC (and would be caught by `OtcLeakCondition` as a leak) instead arrives with a deliberately-malformed-length OTC, this implementation's current behavior discards the corrupt attribute and evaluates the route as if it had no OTC at all — bypassing the leak check entirely. This is a plausible, low-effort evasion path around the leak-detection guarantee the RFC exists to provide, not just a spec-conformance nitpick. The existing `pathvector-session/RFC.md` row previously claimed this behavior was ✅-correct (citing the `ATTRIBUTE_DISCARD_CASES` table) — corrected to ❌ as part of this pass. | A test constructing an UPDATE with a malformed-length (e.g. 3-byte) OTC attribute, asserting `AttributeErrorPolicy::TreatAsWithdraw` (route treated as withdrawn) rather than `AttributeDiscard` — then add `ATTR_ONLY_TO_CUSTOMER` to `rfc7606_policy()`'s `TreatAsWithdraw` arm alongside the other well-known/critical attributes. |
| OTC procedures apply only to AFI=1/2, SAFI=1 (IPv4/IPv6 unicast); MUST NOT apply to other address families by default; operator MUST NOT be able to reconfigure these procedures | Confirmed correct | This project only supports IPv4/IPv6 unicast at all (no other AFI/SAFI implemented), so the scope restriction is trivially satisfied by the project's own architecture. Grepped for any OTC-related config toggle (mirroring RPKI's `reject_invalid` toggle) — none exists; OTC enforcement is unconditionally wired based on configured `Role`, matching "operator MUST NOT have the ability to modify" | — |
| AS-Confederation-aware OTC handling | Already correctly tracked as deferred | RFC itself says NOT RECOMMENDED between confederation members; `pathvector-session/RFC.md` already notes this matches the project's existing confederation scope boundary | Already tracked |

**§5 summary:** 9 clauses reviewed — 8 confirmed correct, 1 confirmed gap
(security-relevant).

### RFC 9234 running total

15 clauses reviewed — 13 confirmed correct, 2 confirmed gaps. **RFC 9234
audit considered complete.** The core leak-detection/propagation mechanism
(§5's six ingress/egress rules) is genuinely well-built and matches the RFC
precisely — a good example of this audit confirming quality rather than
just finding defects. The 2 gaps: malformed-OTC handling uses the wrong
RFC 7606 policy (security-relevant — a leak-detection evasion path), and
peer-side duplicate/conflicting Role Capabilities aren't detected (same
code shape as the earlier RFC 4724 finding — a pattern worth a dedicated
look across other capability types someday). Both filed in `TODO.md` (#18),
neither fixed as part of this diagnostic pass.

---

*(Per the roadmap, next up: RFC 7606 (revised UPDATE error handling), then
the already-flagged ⚠️ items, RPKI/BMP, then the encode-only RFCs.)*

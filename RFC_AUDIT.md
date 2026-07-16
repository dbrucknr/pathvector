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

*(Sections §1–3 and §8–§10 not yet covered by this audit pass — §8's
connection-collision-coordination sub-topic is already covered above under
§6.8, so what remains of §8 is the FSM state-transition table itself, largely
already battle-tested via the earlier fault-injection work; §9 (decision
process/update-send/MRAI) and §10 (timers) are next per the roadmap.)*

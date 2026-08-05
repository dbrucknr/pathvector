# Changelog

All completed implementation items, extracted from TODO.md and organized by completion date.

---

## 2026-08-05 (round 2: additional e2e coverage gaps, Codex follow-up review)

### [pathvector-e2e] Selection Deferral wait-set must cover the full configured peer set, not just one peer's EOR

A follow-up Codex review of the PR #50 gap closure (below) pointed out that
the single-source `SelectionDeferralHarness` cannot distinguish "the
wait-set correctly waits on every configured GR peer" from "the wait-set
incorrectly releases as soon as any one peer sends EOR" — both produce
identical observable behavior with only one GR peer configured. The
underlying `daemon/deferral.rs::recompute` algorithm already iterates the
full configured peer set correctly (a first design draft that only checked
established peers was caught during planning review — see that module's
doc comment), but nothing had proven this at the real-session level.

Added an `eor-immediately` scenario to `mock_bgp_gr_peer.rs` (sends its EOR
the instant the handshake completes, no route announced) and a
`TwoSourceSelectionDeferralHarness` (`pathvector-e2e/src/lib.rs`) running
two independent GR-capable mock peers plus a plain GoBGP observer. New test
`fast_eor_from_one_source_does_not_release_wait_set_for_the_other`
(`pathvector-e2e/tests/selection_deferral.rs`): one source sends its EOR
immediately, the other (`withhold-eor`) never does; asserts the observer
does not receive the route right after the fast EOR, and only receives it
once the Selection_Deferral_Timer itself expires.

Real-teeth verified: temporarily patched `SelectionDeferral::recompute` so
that any single peer's EOR release the whole wait-set (ignoring the rest of
the configured peer set), confirmed the new test failed with the exact
diagnostic (route present at the observer immediately after the fast EOR,
well before the timer deadline), reverted (`git diff --stat` confirmed a
clean no-op diff) and reran green.

### [pathvector-e2e] PR #49 unrecognized-transitive-attribute relay had no full-pipeline e2e coverage

Codex's review of PR #49 found the existing coverage for RFC 4271 §5's
unrecognized-transitive-attribute handling — accept, store, and re-forward
with the Partial bit set — was decode-level and daemon-storage-level only.
Nothing proved the complete decode → daemon storage → RIB →
outbound-reconstruction → encode pipeline through a real relay, and a GoBGP
CLI's rendered RIB text can't assert an exact re-encoded flags octet anyway.

Added a new mock binary, `mock_bgp_attr_peer.rs`, playing either a `source`
role (injects an unrecognized Optional+Transitive attribute with the
Partial bit deliberately clear, plus an unrecognized Optional-only
non-transitive attribute as a negative control) or an `observer` role
(decodes pathvectord's re-advertised UPDATE with the real wire codec and
logs a `SCENARIO_OUTCOME:` line). New `UnknownTransitiveAttrHarness`
(`pathvector-e2e/src/lib.rs`) and test
`unknown_transitive_attribute_relayed_with_partial_bit_set`
(`pathvector-e2e/tests/unknown_transitive_attribute.rs`) assert the
transitive attribute survives with its value unchanged and the Partial bit
now set, while the non-transitive one never reaches the observer.

Real-teeth verified in two independent places: (1) temporarily disabled
`pathvector-session`'s Partial-bit-setting logic on re-encode — confirmed
the test failed with `partial_bit_set=false`; (2) temporarily widened
`pathvectord`'s attribute-storage guard to also store non-transitive
unknown attributes — confirmed the test failed with
`nontransitive_present=true`. Both reverted (clean no-op diffs) and
reconfirmed passing.

### [pathvector-e2e] RFC 5065 §5 condition 2 (confed-member peer, wrong-first-segment AS_PATH) had no e2e coverage

The RFC 5065 confederation-member support PR added e2e coverage for §5
condition 1 (an ordinary `External` peer sending a confederation segment),
but condition 2 — a peer pathvectord is actually configured to treat as a
fellow confederation Member-AS, whose AS_PATH doesn't lead with
`AS_CONFED_SEQUENCE` — had none.

Added two `mock_bgp_fault_peer.rs` scenarios
(`rfc5065-confed-member-wrong-first-segment-with-nlri`/`-no-nlri`, mirroring
condition 1's pair) and `FaultInjectionHarness::new_confed_member`, which
configures pathvectord with a `confederation_id` and marks the fault peer
`confederation_member = true` so it's genuinely classified as
`PeerType::ConfedMember`. Also added `write_gobgp_config_confed_control`:
once `confederation_id` is set, pathvectord presents that value — not its
private Member-AS number — toward peers it classifies as `External` (RFC
5065 §4.1(c)), so the plain control peer's GoBGP config needs a matching
`peer-as` or it rejects pathvectord's OPEN with Bad Peer AS. Diagnosed via
a temporary `RUST_LOG=debug` container env var before finding the real
cause (not a pathvectord bug — a test-harness config mismatch).

Real-teeth verified: disabled the `malformed_from_confed_member` check in
`daemon/route.rs`, confirmed both new tests failed for the right reason,
reverted (clean no-op diff) and reconfirmed passing. Full `fault_injection`
suite (18/18) regression-clean.

## 2026-08-05 (e2e/integration test gaps identified by Codex review of PR #48 and PR #50)

### [pathvector-session] PR #48 (docs-only) — one test's "real NOTIFICATION bytes on the wire" claim was inaccurate

Review of PR #48 found that `test_unrecognized_well_known_attribute_sends_correct_notification_and_terminates`
uses `MockTransport` and injects a pre-decoded `MalformedUpdate` directly —
it proves the FSM picks the right NOTIFICATION given that input, but never
exercises the actual byte-level decoder that classifies a raw attribute as
"unrecognized well-known" in the first place, nor the NOTIFICATION's own
wire encoding.

Added `test_raw_unrecognized_well_known_attribute_sends_real_notification_bytes`
to `pathvector-session/tests/transport.rs`: a hand-rolled raw UPDATE frame
(Optional bit clear, Transitive bit set, unrecognized type code — RFC 4271
§4.3) goes in over a real loopback TCP socket, decoded by the real
`BgpCodec`, and the NOTIFICATION that comes back out is itself decoded by
the real codec on the peer's side. Mirrors the existing
`raw_update_with_attr`/`accept_and_handshake` pattern already used by the
AGGREGATOR decoding tests in that file.

Real-teeth verified: temporarily disabled the RFC 4271 §6.3
unrecognized-well-known-attribute check, confirmed the new test failed (the
attribute silently fell through as `Unknown`, no NOTIFICATION sent),
restored and reran green. Full transport integration suite (19 tests)
passes.

### [pathvector-e2e] PR #50 — RFC 4724 §4.1 Selection_Deferral_Timer had no real end-to-end coverage

Review of PR #50 found that its four "integration" tests all operate
directly on `DaemonState`, bypassing TOML config parsing, real OPEN
capability negotiation, receiving an actual wire-encoded EOR, the
`tokio::select!` timer branch in `daemon/mod.rs`, and delivery of the
catch-up dump over a real BGP session. The existing Docker e2e suite passed
throughout PR #50 but never configured `selection_deferral_time` at all, so
it supplied regression coverage without ever exercising the new feature.

Added a new mock binary, `mock_bgp_gr_peer.rs` (+ `mock-bgp-gr-peer` Docker
stage, Justfile target, and CI step, mirroring `mock_bgp_fault_peer`'s
established pattern), with two scenarios: `withhold-eor` (advertises GR
with a nonzero `restart_time`, announces a route, then never sends EOR) and
`restart-time-zero-delayed-eor` (advertises GR with `restart_time == 0` —
RFC 4724 §3's EOR-only mode — announces the same route, then sends EOR
after a fixed delay). `SelectionDeferralHarness` (pathvectord + this mock
as the GR-capable "source" + a plain GoBGP "observer") and
`pathvector-e2e/tests/selection_deferral.rs`'s two tests validate the full
path Codex asked for:

- `route_withheld_from_observer_until_deferral_timer_expires`: the route
  reaches pathvectord's own Loc-RIB immediately (deferral is scoped to
  outbound advertisement only) but is withheld from the observer until the
  Selection_Deferral_Timer force-releases and flushes it.
- `restart_time_zero_peer_blocks_release_until_its_own_eor_arrives`: a
  `restart_time == 0` peer still blocks the wait-set until its own real EOR
  arrives (not exempted just because it claims no forwarding-state
  preservation) — release happens well before a deliberately much longer
  deferral deadline, distinguishing the wait-set-satisfied path from the
  timer-expiry path. This is exactly PR #50's own P1 fix (EOR-only GR peers
  must stay in the deferral wait-set), now proven over a real session.

Real-teeth verified both: reverted PR #50's P1 fix
(`gr_advertised_peers` insertion gated on `peer_gr_time.is_some()` instead
of unconditionally on `peer_gr_advertised`), confirmed
`restart_time_zero_peer_blocks_release_until_its_own_eor_arrives` failed
(route reached the observer within ~1-2s, before the mock's 3s EOR delay);
separately forced `SelectionDeferral::new` to always construct disabled,
confirmed `route_withheld_from_observer_until_deferral_timer_expires`
failed (route reached the observer immediately); restored both and reran
green.

---

## 2026-08-05 (RFC 5065: 4 blocking fixes from external code review of PR #51)

### [pathvectord, pathvector-session] External code review found four real gaps in the RFC 5065 Member-AS work below — all four confirmed against directly-fetched RFC text and fixed

An external review of PR #51 (RFC 5065 full Member-AS support, entry
below) identified four blocking issues. Each was independently re-verified
against directly-fetched RFC text (not from memory, not taking the review's
word for it) before fixing:

1. **External OPENs still advertised the private Member-AS Number, not the
   Confederation Identifier.** RFC 5065 §4: "A member of a BGP
   confederation MUST use its AS Confederation Identifier in all
   transactions with peers that are not members of its confederation...
   this number is used in OPEN messages... MUST use its Member-AS Number
   in all transactions with peers that are members of the same
   confederation." The original work applied this only to AS_PATH
   generation, missing the session's own `my_as` field and `FourByteAsn`
   capability. Added `FsmConfig.public_as`/`SessionConfig.public_as`
   (`pathvector-session`) and `effective_session_as` (`pathvectord`),
   threaded through every session-spawn site (static startup, dynamic
   `AddPeer`) and the reconnect capability-refresh path.

2. **RFC 5065 §5's two malformed-AS_PATH conditions were session-reset;
   RFC 7606 §3(e) actually reclassifies them as treat-as-withdraw.** The
   original reasoning — RFC 5065 is absent from RFC 7606's formal
   "Updates: 1997, 4271, 4360, 4456, 4760, 5543, 5701, 6368" list, so its
   citation of RFC 4271 §6.3 stays literal — was wrong. RFC 7606 §3 states
   "This specification amends Section 6.3 of [RFC4271]," and §3(e): MUST
   use treat-as-withdraw "for the cases that specify a session reset and
   involve any of the attributes ORIGIN, AS_PATH, NEXT_HOP,
   MULTI_EXIT_DISC, or LOCAL_PREF." RFC 5065 §5 delegates to "the
   procedures of [BGP-4], Section 6.3" by reference rather than hard-coding
   session-reset itself, and both conditions specify a session reset
   involving AS_PATH — so RFC 7606's amendment to the referenced procedure
   text applies regardless of RFC 5065's absence from the formal
   "Updates:" list, which names documents RFC 7606 edits directly, not
   every document that cites §6.3. This ends up matching BIRD's actual
   practice after all — just derived from RFC text rather than trusted
   from BIRD's behavior or the Updates-list heuristic alone. The one
   preserved exception is RFC 7606 §3(j)/§5.2 (session reset when NLRI
   wasn't parseable), handled by gating the RFC 5065 §5 checks on
   `notification.is_none()` so an already-decided §5.2 reset wins.

3. **An empty AS_PATH from a `ConfedMember` peer was wrongly exempted.**
   The original condition-2 check required `!as_path.is_empty()` before
   flagging a missing leading `AS_CONFED_SEQUENCE`. RFC 5065 §5's actual
   wording has no such exemption ("does not have AS_CONFED_SEQUENCE as the
   first segment" — an empty path has no first segment at all), and §4.1(b)
   requires even an originated route sent to a neighboring Member-AS to
   carry a ConfedSequence. Removed the exemption; folded into the same
   condition-2 check as a natural consequence of `.first()` returning
   `None` for an empty path.

4. **AS4_PATH could carry AS_CONFED_SEQUENCE/AS_CONFED_SET segments.**
   RFC 6793 §§3, 4.2.2: these segment types "are declared invalid for the
   AS4_PATH attribute and MUST NOT be included." `route_to_attributes`/
   `route_v6_to_attributes` built AS4_PATH from the full original
   (pre-downgrade) path, which — once RFC 5065 relaying could legitimately
   leave confed segments in a route sent to a `ConfedMember` peer — could
   propagate those segments into AS4_PATH when the same route was later
   downgraded for a two-byte-only peer. Fixed by applying the existing
   `AsPath::strip_confed_segments()` to the AS4_PATH value specifically,
   leaving the (downgraded) wire AS_PATH untouched.

Real-teeth verified: fix #1's `make_open` change (reverted, confirmed
`test_sent_open_uses_public_as_not_local_as` failed with `left: 65001,
right: 64512`, restored); fix #4's AS4_PATH strip (reverted, confirmed
`as4_path_excludes_confed_segments_for_two_byte_peer` failed with the
confed ASN present in AS4_PATH, restored). Fixes #2/#3 rewrote the
existing test suite's expectations from session-reset to treat-as-withdraw
(the tests' own prior assertions were the thing proven wrong, not new
code) plus one new explicit empty-AS_PATH regression test.

See `pathvector-session/RFC.md` and `pathvectord/RFC.md`'s RFC 5065
sections for the full corrected requirement tables.

### [pathvectord] Follow-up review pass: RFC 5065 §5 treat-as-withdraw was a silent no-op on UPDATEs with no reachable NLRI

A second review pass on the fixes above found one remaining gap in the
treat-as-withdraw fix (finding #2): when an UPDATE carrying a malformed
AS_PATH (RFC 5065 §5) has no announced NLRI at all — no traditional NLRI,
no MP_REACH_NLRI — draining the (empty) announced-NLRI list into
withdrawals does nothing, and no NOTIFICATION was sent either, so the
malformed condition was silently ignored. RFC 7606 §5.2: "if an UPDATE
message is encountered that does contain path attributes other than
MP_UNREACH_NLRI and doesn't encode any reachable NLRI... if any path
attribute errors are encountered in such an UPDATE message and if any
encountered error specifies an error-handling approach other than
'attribute discard', then the 'session reset' approach MUST be used."
Treat-as-withdraw is "other than attribute discard," so this exact case
requires session reset, not a silent no-op.

Fixed by branching the RFC 5065 §5 checks on the already-existing
`has_reachable_nlri_on_wire` variable: treat-as-withdraw when there's
reachable NLRI to drain, `MalformedAsPath` NOTIFICATION/session-reset
otherwise. Real-teeth verified (forced the old `if true` no-op branch,
confirmed all three new regression tests failed with `got None`, restored
and reran green). Added regression tests for both RFC 5065 §5 conditions
with no reachable NLRI, including the empty-`ConfedMember`-path case.

Full workspace re-verified after this fix: `cargo build --workspace`,
`cargo clippy -p pathvectord --all-targets -- -D warnings`, `cargo fmt
--all -- --check`, `cargo nextest run --workspace --exclude
pathvector-e2e` — 1967/1967 passing.

### [pathvector-e2e] Real end-to-end coverage for RFC 5065: a 3-node confederation interop harness and two new fault-injection scenarios

Everything above (both the original RFC 5065 Member-AS work and the
review-driven fixes) was verified at the unit level only — hand-built
`UpdateMessage`/`Route` structs and `handle_update` calls, never a real
wire codec exchanging bytes with a real BGP implementation. Requested
explicitly after PR #51 merged (user-prioritized: real confederation
interop first, then the two RFC 5065 §5 error-handling scenarios fitted
into the existing fault-injection harness).

**`ConfederationHarness`** (`pathvector-e2e/src/lib.rs`) stands up
pathvectord as a real confederation Member-AS (local_as 65001,
confederation_id 64512) against two real peers: FRR configured as a
fellow Member-AS via FRR's own `bgp confederation identifier`/`bgp
confederation peers` directives (FRR is confederation-aware — a plain
eBGP speaker would originate routes with an ordinary AS_SEQUENCE, not
the AS_CONFED_SEQUENCE RFC 5065 §5 requires from a fellow Member-AS
peer), and a genuinely external GoBGP peer whose config expects the
confederation identifier in pathvectord's OPEN rather than the private
Member-AS — itself part of the interop proof, since a `public_as`
regression would make that specific session fail to establish (Bad Peer
AS) while the FRR session still came up fine.
`pathvector-e2e/tests/confederation.rs`'s three tests confirm both
sessions establish with the correct visible AS, a route originated by
FRR crosses to the external peer with confederation segments fully
stripped (checked against real `gobgp global rib` output — AS_PATH
shows only `64512`, no trace of either private Member-AS number), and a
route originated by the external peer crosses to FRR with a prepended
confederation segment (checked against real FRR `vtysh show bgp`
output: `(65001) 65099`, with FRR's own `confed-external` status
marker).

**Two new `mock_bgp_fault_peer` scenarios**
(`rfc5065-confed-segment-with-nlri`, `rfc5065-confed-segment-no-nlri`)
exercise RFC 5065 §5's two malformed-AS_PATH conditions over a real BGP
session with the real wire codec on both ends, mirroring the file's
existing `missing-origin`/`duplicate-mp-reach` scenario shapes — both
fully expressible via `AsPath`/`AsPathSegment` with no raw-byte
hand-rolling needed, unlike the invalid-ORIGIN-byte scenarios elsewhere
in the file.

Real-teeth verified end to end: temporarily disabled
`strip_confed_segments()` in `pathvector-rib`'s `prepare_outbound`,
rebuilt the pathvectord Docker image, confirmed the route-crossing test
failed (the malformed export never even reached the external GoBGP
peer — GoBGP itself refuses to accept it), restored and reran green;
the two fault-injection scenarios were verified the same way against
`daemon/route.rs`'s RFC 5065 §5 check (temporarily forced to its old
no-op branch). Full `pathvector-e2e` suite (129 tests, all harnesses)
passes with no regressions from the `lib.rs` additions.

---

## 2026-08-04 (RFC 5065: full BGP Confederation Member-AS support)

### [pathvector-types, pathvector-rib, pathvector-session, pathvectord, pathvector-client] Originate/relay as a confederation Member-AS, not just pass-through interop

Prior to this work, RFC 5065 support was pass-through/interop only —
correctly stripping confederation segments from routes relayed from
someone else's confederation, but with zero representation for
*originating or relaying as an actual confederation Member-AS*: `PeerType`
had only `Internal`/`External`/`Local`, and there was no confederation
config schema at all. Flagged as "significant, architectural, not a quick
fix" by `RFC_AUDIT.md`'s 2026-07-16 audit-the-audit finding and filed as
its own initiative (`TODO.md` task #128) rather than folded into the
smaller RFC 4271/9234/1997 fixes shipped earlier this session.

Grounded in three research passes, not memory: RFC 5065's full text (§4.1
AS_PATH modification rules, §5 error handling, §5.1-§5.3 NEXT_HOP/MED/
LOCAL_PREF/best-path exceptions); RFC 1997's exact `NO_EXPORT` vs.
`NO_EXPORT_SUBCONFED` wording; and RFC 7606's own scope statement ("This
document updates error handling for RFCs 1997, 4271, 4360, 4456, 4760,
5543, 5701, and 6368") — RFC 5065 is absent from that list, so its two new
malformed-AS_PATH conditions (§5) are implemented as session-reset, not
treat-as-withdraw, a deliberate departure from BIRD's more lenient
practice matching the precedent this session already established for RFC
4271 §6.3 (see the entry below).

**New:** `PeerType::ConfedMember`, `AsPath::prepend_confed()`,
`DaemonConfig.confederation_id`/`PeerConfig.confederation_member` config
schema, `FsmConfig.confederation_member` (the authoritative classifier for
live Established sessions), `config_peer_type`/`effective_confederation_member`
(the pre-Established/post-disconnect classifier), an explicit best-path
rank function (`ConfedMember` ties with `Internal`, which `PeerType`'s
derived `Ord` cannot express), the `public_as` outbound parameter
(`confederation_id.unwrap_or(local_as)`), a strip-then-prepend ordering
fix in `prepare_outbound`/`prepare_outbound_v6`, the RFC 1997
`NO_EXPORT`/`NO_EXPORT_SUBCONFED` split, LOCAL_PREF-accept widening,
confederation-ID-aware loop detection, and two new RFC 5065 §5
malformed-AS_PATH session-reset checks.

**Critical finding caught during planning:** `PeerType` is classified in
two independent places workspace-wide — `pathvectord`'s `config_peer_type`
(authoritative only for the pre-Established/post-disconnect windows) and
`pathvector-session`'s FSM (`Fsm::build_session_info`, authoritative for
every live Established session). A design extending only
`config_peer_type` would have shipped a daemon that silently
misclassifies every live confederation-member session as plain
`External` — caught by a dedicated Plan-subagent review pass before any
code was written, independently re-verified by reading `fsm/mod.rs`
directly, the same defensive pattern that caught the RFC 4724 §4.1
EOR-only-peer wait-set bug earlier this session.

**Second finding:** the existing (unmodified) `prepare_outbound`/
`propagate_prefix` pipeline prepended before stripping confederation
segments, producing two separate `Sequence` segments instead of one
canonically-merged one for a route that already carries confed segments —
fixed by reordering to strip-then-prepend inside `prepare_outbound`'s
`External` branch.

Real-teeth verified throughout: the FSM classification fix, the
confederation-ID loop-detection extension, and both RFC 5065 §5
malformed-AS_PATH checks were each reverted, confirmed to fail for the
right reason, then restored and reran green against the full test suite
(pathvector-session: 343 tests; pathvectord: 726 tests).

See `pathvector-types/RFC.md`, `pathvector-rib/RFC.md`,
`pathvector-session/RFC.md`, and `pathvectord/RFC.md`'s RFC 5065 sections
for the full requirement-by-requirement writeup, and `TODO.md` item #128
for the closure note.

---

## 2026-08-04 (RFC 4724 §4.1 Restarting-Speaker Selection_Deferral_Timer)

### [pathvectord] No deferral of our own outbound route advertisement after a daemon restart

RFC 4724 §4.1: a Restarting Speaker "MUST defer route selection for an
address family" until it either receives End-of-RIB from all GR-capable
peers (excluding restarting ones) or a configurable
`Selection_Deferral_Timer` expires. No such mechanism existed anywhere in
the codebase — `handle_update`/propagation ran immediately per-UPDATE with
no notion that this daemon's own restart might still be settling, so a
route could be advertised to one peer moments before a slower peer's
routes arrived and changed the best-path outcome. This project's existing
GR work covered the *Receiving Speaker* role (holding a peer's stale
routes during *their* restart) well; the *Restarting Speaker* role
(deferring *our own* decisions after *our* restart) had no code path.

Researched BIRD's actual source (`nest/proto.c`'s doc comment, not
trained-in memory of "how BIRD generally works") before scoping: BIRD
implements this by deferring **export only** — Loc-RIB/route selection
itself stays immediate; only outbound advertisement to peers is held back
while tables refill. Adopted the same scope here, over the RFC's more
literal "defer route selection" text, per explicit direction to match
BIRD's real-world practice. New `selection_deferral_time` config field
(`[daemon]`, seconds, `0` disables) applies on **every** startup when
nonzero — deliberately not gated behind the pre-existing `restarting` flag
(which only controls the R-bit), since incomplete peer state on startup is
a risk regardless of whether the restart was planned.

New `SelectionDeferral` struct (`pathvectord/src/daemon/deferral.rs`)
tracks a one-way per-family (v4/v6) latch. `recompute()` implements the
wait-set: a family blocks release for every peer in the **full configured
peer set** that is either not yet established, or established-and-GR-capable-
and-not-itself-restarting-and-hasn't-sent-EOR. Using the full configured
set rather than just currently-established peers was a deliberate
correction — a design-review pass caught that an established-only
wait-set would let one fast peer's EOR falsely satisfy the wait-set before
a slower peer even attempted its TCP connection, defeating the feature in
the ordinary multi-peer-restart case. `force_release()` implements the
Selection_Deferral_Timer expiry path (b), overriding an unsatisfied
wait-set unconditionally.

`propagate_prefix`/`propagate_prefix_v6` (`outbound.rs`) gained a
`deferred: bool` parameter: when `true`, returns `NoChange` immediately
without touching `loc_rib`/`adj_rib_out`/`export_policy` at all, so
nothing needs reconciling once the gate genuinely opens — an earlier
design draft considered filtering announcements out downstream in
`flush_updates` instead, but that would have left AdjRibOut believing a
route was sent when it wasn't. `on_established`'s initial full-table dump
is now independently gated per family (skipped entirely, no EOR sent,
while deferred); `recompute_selection_deferral` — triggered on EOR
receipt, peer establishment, and permanent peer removal — runs a gate-open
catch-up (full dump + EOR) across every currently-established peer once a
family transitions to released. A new event-loop `tokio::select!` arm
fires the Selection_Deferral_Timer itself, calling a dedicated
`force_release_selection_deferral()` that drives the catch-up directly off
`force_release`'s own return value — calling plain `force_release()`
followed by `recompute_selection_deferral()` was tried first and found (by
its own new test going red) to silently skip the catch-up entirely, since
`force_release` already flips both released flags before `recompute()`
runs, leaving nothing for it to see as "newly transitioned."

13 new `daemon::deferral::tests` (wait-set membership rules including the
corrected full-configured-peer-set semantics, one-way latch, force-release
override), 4 new `outbound::propagate_tests` (deferred suppresses
Announce/Withdraw for both v4 and v6, AdjRibOut left completely
untouched), 4 new `daemon::selection_deferral_tests` (gate blocks
propagation until EOR then catches up; an unestablished configured peer
keeps the gate closed even after other peers EOR; forced release
overrides an unsatisfied wait-set and still catches up; `0` is a true
no-op regression guard). Real-teeth verified: reverted the
configured-peer-set wait-set fix back to established-only and confirmed
the corresponding test failed with the expected diagnostic; reverted the
`propagate_prefix` deferred early-return and confirmed the corresponding
test failed; both restored and reconfirmed passing. The
`force_release`/`recompute_selection_deferral` ordering bug was caught the
same way, just not injected deliberately — the first version of the test
suite found it on its own. Full workspace build/test (713 passing in
`pathvectord`), `cargo fmt`, and `cargo clippy -D warnings` clean.

### [pathvectord] Follow-up: EOR-only (`restart_time = 0`) GR peers were wrongly excluded from the deferral wait-set

A Codex review on the PR carrying the above feature caught a real
RFC-compliance bug before merge: RFC 4724 §3 explicitly recommends
advertising the GracefulRestart capability with `restart_time == 0` and no
`<AFI, SAFI>` families specifically to signal "I don't preserve forwarding
state, but I will still generate End-of-RIB" — and §4.1's Restarting-Speaker
wait-set excludes only peers that "do not advertise the graceful restart
capability" at all, not peers advertising it with `restart_time == 0`.
`extract_gr_capability()` collapsed the zero-time case to the same `None`
result used for "no capability sent at all," so the deferral wait-set (which
was consulting `gr_capable_peers`, itself correctly `restart_time > 0`-gated
for its actual purpose — stale-route retention) treated an EOR-only peer as
non-GR and released the gate before that peer's EOR arrived, defeating the
feature for the project's own documented default configuration
(`graceful_restart_time = 0`).

Fetched RFC 4724 §3/§4.1 again directly to confirm the exact wording before
fixing. Added `RibSnapshot::gr_advertised_peers: HashSet<IpAddr>` as a signal
distinct from `gr_capable_peers`: populated whenever a GracefulRestart
capability was present at all, regardless of `restart_time`.
`extract_gr_capability()` now returns a separate `advertised: bool` alongside
`restart_time: Option<u16>` (still `None` for the zero case, preserving the
existing stale-route-retention semantics `gr_capable_peers` needs), and
extracts the R-bit unconditionally whenever a capability is present — the
previous version only extracted it inside the `restart_time > 0` branch, so
an EOR-only peer's own Restart State bit was silently discarded and
`gr_peer_restarting` was never set for it either. `deferral.rs`'s
`family_blocks`/`recompute` now consult `gr_advertised_peers` instead of
`gr_capable_peers`.

New test `eor_only_gr_peer_keeps_gate_closed_until_its_eor`
(`daemon::selection_deferral_tests`) establishes a peer advertising GR with
`restart_time = 0` and confirms the gate stays closed until that peer's own
EOR arrives. Real-teeth verified: reintroduced the `restart_time > 0`
collapse in `extract_gr_capability()`, confirmed the new test failed with
exactly the diagnostic the review predicted, then restored and reconfirmed
passing. Full `pathvectord` test suite (717 passing), `cargo fmt`, and
`cargo clippy -D warnings` clean.

---

## 2026-08-04 (RFC 4271 §6.3: revert treat-as-withdraw back to session-reset)

### [pathvector-session] Restored RFC-4271-literal session-reset for unrecognized well-known attribute

A code review (Codex) on the branch carrying yesterday's treat-as-withdraw
revision (below) flagged it as a compliance regression before it merged.
On reflection, correctly so: RFC 4271 §6.3's requirement here is an
unamended MUST, not an area the RFC leaves ambiguous — confirmed again
that RFC 7606's §3 revisions are an explicit, exhaustive (a)-(j) list that
never touches this subcode. "A specific other implementation (BIRD) does
X" is a fine tie-breaker when the RFC text itself is genuinely silent or
underspecified (as with RFC 4724 §4.1's Restarting-Speaker deferral
scope), but it isn't a valid basis for deviating from unambiguous RFC
text just because the RFC's chosen behavior (full session reset) is
stricter than what's convenient.

Restored `AttributeErrorPolicy::SessionReset { error, data }` and the
exact decode/transport-layer behavior from the original 2026-07-31 fix by
checking out that commit's version of `pathvector-session/src/message/update.rs`
and `pathvector-session/src/transport/mod.rs`, rather than reimplementing
from scratch — guarantees an exact match rather than a close
approximation. All three original tests are back:
`test_unrecognized_well_known_attribute_is_session_reset`,
`test_unrecognized_well_known_attribute_extended_length_data_field`, and
`test_unrecognized_well_known_attribute_sends_correct_notification_and_terminates`.

Real-teeth re-verified: reintroduced yesterday's treat-as-withdraw policy,
confirmed the two decode-level tests failed for the right reason, restored
and reconfirmed passing. Full `pathvector-session` test suite (341 unit +
18 integration + 2 doctests) green.

## 2026-08-03 (RFC 4271 §6.3 policy revision: session-reset → treat-as-withdraw)

### [pathvector-session] Unrecognized well-known attribute now treat-as-withdraw, matching real-world practice instead of the literal RFC 4271 text

The 2026-07-31 fix for this clause implemented RFC 4271 §6.3 literally:
an unrecognized attribute with the Optional bit clear triggers
NOTIFICATION(UPDATE Error, Unrecognized Well-known Attribute) and a full
session reset, since RFC 7606's §3 revisions are an explicit, exhaustive
(a)-(j) list that never mentions this subcode. Asked what a real-world
implementation actually does here rather than relying on the literal
text alone: checked BIRD's source directly
(`proto/bgp/attrs.c`'s `bgp_decode_attrs`). For exactly this case, BIRD
uses its `WITHDRAW` path (`s->err_withdraw = 1`, session stays up), not
`REJECT` (session reset) — extending RFC 7606's "minimize blast radius"
philosophy to a clause it doesn't explicitly cover, rather than the
stricter literal-RFC-4271 reading. This project now follows the same
practice: an ordinary peer sending one unrecognized attribute (version
skew, a vendor extension) shouldn't tear down the whole session over it.

Changed the policy from `SessionReset` to `TreatAsWithdraw` in
`decode_path_attributes`. This let `AttributeErrorPolicy::SessionReset`
revert to a unit variant (only the pre-existing duplicated
MP_REACH_NLRI/MP_UNREACH_NLRI case still uses it, RFC 7606 §3(g)),
`handle_malformed_update` revert to its simpler hardcoded-NOTIFICATION
form, and removed the now-obsolete Data-reconstruction logic entirely —
a net simplification on top of the policy change, not just a flip.
Renamed the decode-level test to
`test_unrecognized_well_known_attribute_is_treat_as_withdraw` (dropped
the now-irrelevant extended-length Data-field variant) and removed the
dedicated session-level NOTIFICATION test — the transport layer no
longer has any behavior specific to this clause, since it's fully
absorbed into the pre-existing generic treat-as-withdraw pathway
(already proven by `test_rfc7606_treat_as_withdraw_keeps_session_up_and_withdraws_nlri`).

Real-teeth verified: flipped the policy back to `SessionReset` and
confirmed the renamed decode-level test failed with the exact expected
diagnostic; restored and reconfirmed passing. Full workspace
build/test, `cargo fmt`, and `cargo clippy` clean.

---

## 2026-08-03 (RFC 4271 §5 unrecognized-transitive-attribute storage)

### [pathvector-types, pathvector-rib, pathvectord] Unrecognized transitive optional attributes couldn't survive a relay through this router

RFC 4271 §5: "Paths with unrecognized transitive optional attributes
SHOULD be accepted [and] passed... to other BGP peers with the Partial
bit... set to 1. Unrecognized non-transitive optional attributes MUST be
quietly ignored and not passed along." `Route`/`RareAttrs`
(`pathvector-rib`) had no field of any kind for an opaque/unrecognized
attribute, so any unrecognized attribute — transitive or not — was
unconditionally dropped the moment a route was accepted into the RIB.
This was a real transit-correctness concern: any future/foreign BGP path
attribute riding through this router as a transit AS would have been
silently stripped, not just an incomplete-coverage gap.

Checked what a real-world implementation does before scoping this: BIRD
(`proto/bgp/attrs.c`) already stores unknown attributes generically as
opaque bytes in its extended-attribute system and re-exports transitive
ones with the Partial bit set — confirming this really was "just" a
data-model gap, not a deeper architectural problem.

Added `pathvector_types::UnknownAttribute { type_code: u8, value: Vec<u8> }`
rather than having `pathvector-rib` depend on `pathvector-session`'s
wire-level `PathAttribute` type directly — both crates already depend on
`pathvector-types`, so this avoids a new dependency edge between
siblings. Only the type code and raw value bytes are stored: only the
Optional=1,Transitive=1 combination is ever stored (matching RFC 4271
§5's own text), and re-encoding always emits that flag combination
unconditionally — `pathvector-session`'s own encoder then sets the
Partial bit for exactly that combination, correctly ignoring whatever
the incoming Partial bit was (forwarding an attribute we didn't
originate/verify always requires Partial=1).

`RareAttrs` gained `pub unknown: Vec<UnknownAttribute>` following the
existing lazy-allocate-on-first-write pattern used for
communities/cluster_list/etc.; `RouteBuilder` gained
`.unknown_attribute(attr)` mirroring `.community(c)`. On ingest,
`handle_update`'s attribute loop gained a match arm for
`PathAttribute::Unknown` guarded on both flag bits, wired into both the
IPv4 and IPv6 `RouteBuilder` construction sites. On egress,
`route_to_attributes`/`route_v6_to_attributes` forward stored unknown
attributes unconditionally regardless of peer type — matching how OTC
(RFC 9234 §3, also optional+transitive) is already handled, since RFC
4271 §5 doesn't gate transitive-attribute forwarding on peer type
either.

4 new tests across ingest, egress, and the new type itself. Real-teeth
verified: removed the new `handle_update` match arm and confirmed the
storage test failed with the exact expected diagnostic; separately
removed the new outbound calls and confirmed the egress test failed;
both reverts restored and reconfirmed passing. Full workspace
build/test, `cargo fmt`, and `cargo clippy` clean.

---

## 2026-08-03 (RFC 4271 §4.1 trailing-padding rejection)

### [pathvector-session] OPEN and ROUTE_REFRESH silently accepted trailing padding within the declared header Length

RFC 4271 §4.1: "'padding' of extra data after the message is not allowed.
Therefore, the Length field MUST have the smallest value required, given
the rest of the message." `decode_with_limit`'s `Keepalive` arm already
checked `cur.remaining() != 0` after decode, but the `Open` and
`RouteRefresh` arms didn't — a message with extra bytes inside the
declared frame length (beyond what OPEN's capabilities or
ROUTE_REFRESH's fixed 4-byte body actually need) was silently accepted
with the padding discarded. Low severity (permissive, not corrupting),
found by the original systematic clause audit (`RFC_AUDIT.md`), the last
remaining gap in RFC 4271 §4.

Checked RFC 7606 and RFC 8654 directly for an amendment — neither
mentions padding, so RFC 4271's original text stands. Added the same
`cur.remaining() != 0` check to the `Open` and `RouteRefresh` match arms
in `decode_with_limit_and_caps`, mirroring the pre-existing `Keepalive`
check exactly. `Update` and `Notification` remain correctly unaffected —
both are required by the RFC itself to consume the rest of the message.

3 new tests: a minimal (no-capabilities) OPEN with one trailing byte, an
OPEN with a real capability plus one trailing byte (ruling out the check
being accidentally tied to the empty-capabilities case), and a
ROUTE_REFRESH with one trailing byte. Real-teeth verified: reverted each
of the two new checks in turn, confirmed the corresponding test(s) failed
with the exact expected diagnostic, then restored and reconfirmed
passing. Full workspace build/test, `cargo fmt`, and `cargo clippy`
clean.

This closes out every gap the original 2026-07-16 systematic clause
audit found in RFC 4271 §4 — the section is now fully ✅.

---

## 2026-07-31 (RFC 4271 §6.2/§6.3 unrecognized-parameter/attribute rejection)

### [pathvector-session] Unrecognized OPEN optional parameter types and unrecognized well-known UPDATE attributes were silently accepted instead of rejected

Two shovel-ready gaps left over from the original systematic clause audit
(`RFC_AUDIT.md`, item #14 in TODO.md), both about a well-formed message
from a technically-valid peer that a strict reading of RFC 4271 requires
rejecting outright:

- **§6.2**: `decode_capabilities` silently skipped any OPEN Optional
  Parameter whose Parameter Type wasn't 2 (Capabilities) — a comment in
  the code said as much. §6.2: "If one of the Optional Parameters in the
  OPEN message is not recognized, then the Error Subcode MUST be set to
  Unsupported Optional Parameters." Fetched RFC 5492 directly to check
  whether it revises this (it doesn't — RFC 5492 §3 confirms this is
  still RFC 4271's own pre-existing mechanism, and only adds a separate,
  finer-grained subcode for an unsupported capability *inside* an
  already-recognized Capabilities parameter). Added
  `CodecError::UnsupportedOptionalParameter`, mapped in
  `header_error_notification` to NOTIFICATION(OPEN Error,
  `OpenMsgError::UnsupportedOptionalParameter`).
- **§6.3**: `decode_attr_value`'s fallback arm treated any unrecognized
  UPDATE attribute type code identically regardless of the Optional bit
  — accepted as `PathAttribute::Unknown` whether the sender claimed it
  optional or well-known. §6.3: "If any of the well-known mandatory
  attributes are not recognized, then the Error Subcode MUST be set to
  Unrecognized Well-known Attribute. The Data field MUST contain the
  unrecognized attribute (type, length, and value)." Fetched RFC 7606
  directly and confirmed its §3 revisions are an explicit, exhaustive
  (a)-(j) list that never mentions this subcode — it remains a full
  session reset, not treat-as-withdraw. `AttributeErrorPolicy::SessionReset`
  widened from a unit variant to `SessionReset { error: NotificationError,
  data: Vec<u8> }` so the pre-existing duplicated-MP_REACH_NLRI case and
  this new case share one code path in `handle_malformed_update` instead
  of the handler hardcoding one specific NOTIFICATION.

Both existing pre-fix tests told the same story this project's testing
discipline exists to catch: `test_unknown_opt_param_type_is_skipped`
asserted the RFC-violating silent-skip as correct behavior by name —
flipped to `test_unknown_opt_param_type_is_rejected`. 7 new tests added
across both clauses (codec-level: unrecognized parameter type, the
deprecated Authentication type-1 parameter, an unrecognized parameter
after valid capabilities; unrecognized well-known attribute in both
1-byte and extended-length encodings; session-level: the actual
NOTIFICATION reaching the wire for both clauses). Real-teeth verified at
every layer — codec-level checks, the NOTIFICATION-mapping function, and
`handle_malformed_update`'s notification-selection logic each reverted in
turn and confirmed to reproduce the exact pre-fix failure before being
restored.

---

## 2026-07-31 (RFC 7606 §7.7 AGGREGATOR capability-dependent length)

### [pathvector-session] AGGREGATOR decode always expected 8 bytes, ignoring whether the 4-octet AS number capability was actually negotiated

RFC 7606 §7.7 requires AGGREGATOR's expected length to depend on whether
RFC 6793's 4-octet AS number capability was negotiated bilaterally with
the peer: 6 bytes (2-byte ASN) if not, 8 bytes (4-byte ASN) if so.
`decode_attr_value`'s `ATTR_AGGREGATOR` arm unconditionally required 8
bytes, with no capability awareness at all — a legitimate 6-byte
AGGREGATOR from a 2-byte-ASN-only peer was silently discarded as
malformed. Low-severity (completeness, not correctness — the *outcome*,
discard, happened to coincidentally match what RFC 7606 wants for a
genuinely malformed AGGREGATOR), deliberately deferred out of the earlier
attribute-flags/OTC cluster (PR 4) as "PR 4b" since it needed
capability-threading into the decoder, an architecture change. Fixed as
PR 4b (`fix/rfc7606-aggregator-capability-length`).

Threaded a `four_byte_asn: bool` through the exact chain scoped in the
original deferral: `decode_attr_value` → `decode_path_attributes` →
`UpdateMessage::decode` → a new `BgpMessage::decode_with_limit_and_caps`
(`pub(crate)`), while leaving the widely-used `BgpMessage::decode`/
`decode_with_limit` entry points unchanged (defaulting to `true`,
preserving ~18 existing call sites across `pathvector-mrt`, benches, and
proptests with no session context). `BgpCodec` gained a
`four_byte_asn_negotiated` field and `set_four_byte_asn()` setter
mirroring the existing RFC 8654 `set_extended_message()` pattern; the
transport layer computes the bilateral negotiation
(`peer_capabilities.contains(FourByteAsn) && local
config.capabilities.contains(FourByteAsn)`) the same way it already does
for `ExtendedMessage`, and calls it from `SessionEstablished` alongside
the existing call.

3 new tests cover both directions of the capability check, plus the
actual completeness fix (a legitimate 6-byte AGGREGATOR from a 2-byte
peer now decodes successfully instead of being discarded). Real-teeth
verified: confirmed the relevant tests failed against the pre-fix
unconditional-8-byte code, confirmed all passed after the fix, then
reverted just the `ATTR_AGGREGATOR` decode arm and confirmed the
identical failures reappeared before restoring. Also fixed a related
issue the change itself exposed: `BgpCodec::new()`'s default needed to
be `true`, not `false`, to stay consistent with `encode_path_attributes`'s
own unconditional 8-byte AGGREGATOR encoding — otherwise generic
`BgpCodec` round-trip proptests (which don't simulate real capability
negotiation) failed.

A Codex review of GH PR #44 raised a non-blocking coverage suggestion (no
code issues found): the decoder-level tests above proved both length
modes in isolation but not that `SessionEstablished`'s negotiation
actually reaches `BgpCodec` in production. Added two real-TCP integration
tests to `tests/transport.rs` driving a genuine loopback session through
`spawn()` (not `MockTransport`, which bypasses the codec), writing
hand-crafted raw UPDATE bytes directly to the socket since the encoder
can't produce a 6-byte AGGREGATOR. Real-teeth verified: temporarily
removed just the `set_four_byte_asn` call from `SessionEstablished`,
confirmed the "not negotiated" integration test failed, then restored.

---

## 2026-07-30 (RFC 5492 Unsupported Capability NOTIFICATION Data field)

### [pathvector-session] NOTIFICATION Data field for a rejected capability encoded only the code, not the full TLV

RFC 5492 §5 requires each capability in an Unsupported Capability
NOTIFICATION's Data field to be "encoded in the same way as it would be
encoded in the OPEN message" — the full `code(1) + length(1) + value`
TLV. `encode_unsupported_capabilities` (`pathvector-session/src/fsm/mod.rs`)
instead built `[code, 0x00]` placeholder pairs, deliberately omitting the
value. Diagnostic-quality impact only — a peer could see *that* a
capability was rejected and its code, but not *which variant* (e.g. which
AFI/SAFI) caused it. Fixed as PR 11 of the RFC audit roadmap
(`fix/rfc5492-unsupported-capability-notification-data`, GH PR #43).

Made `encode_capability_value` (`message/open.rs`) `pub(crate)` and
re-exported it, then rewrote `encode_unsupported_capabilities` to build the
real TLV using that same encoder the OPEN message path already uses —
guaranteeing the two can't drift apart. Checked RFC 8810 (the only RFC
updating RFC 5492) for relevance — it only revises Capability Code IANA
registration ranges, unrelated to error handling.

Added a new test using `MultiProtocol(IPv6 unicast)` rather than the
existing test's `RouteRefresh`, since `RouteRefresh`'s capability value is
empty and can't distinguish the old placeholder encoding from the correct
one. Real-teeth verified: confirmed the new test failed against the
pre-fix code (`[1, 0]` vs expected `[1, 4, 0, 2, 0, 1]`), confirmed it
passed after the fix, then reverted just the encoder function and
confirmed the identical failure reappeared before restoring. Full
`cargo test -p pathvector-session` (329 unit + 16 integration + 2
doctests) and clippy clean.

---

## 2026-07-30 (RFC 1997 well-known community enforcement)

### [pathvector-rib, pathvectord] NO_EXPORT/NO_ADVERTISE/NO_EXPORT_SUBCONFED were defined and decodable but never enforced in outbound propagation

`RFC_AUDIT.md`'s "audit-the-audit" pass (2026-07-16) had flagged this as
overclaiming: `Community::is_no_export()`/`is_no_advertise()`/
`is_no_export_subconfed()` existed and were correctly tested at the type
level, but grepping the entire outbound propagation path
(`propagate_prefix`/`propagate_prefix_v6` in `pathvectord/src/outbound.rs`,
`prepare_outbound`/`AdjRibOut::insert` in `pathvector-rib`) turned up no
call to any of them — a route tagged `NO_EXPORT` or `NO_ADVERTISE`
propagated exactly like an untagged route. Fixed as PR 10 of the RFC audit
roadmap (`fix/rfc1997-well-known-community-enforcement`, GH PR #42).

Added `pathvector_rib::outbound::is_export_suppressed()`, gating both
`propagate_prefix` and `propagate_prefix_v6` immediately after the export
policy evaluates a route as `Accept` — a suppressed route is withdrawn or
left alone exactly like a rejecting policy would, reusing the existing
`Decision::Reject` branch rather than a parallel code path:

- `NO_ADVERTISE` ("MUST NOT be advertised to other BGP peers") blocks every
  peer, internal or external.
- `NO_EXPORT` and `NO_EXPORT_SUBCONFED` both block eBGP peers only. RFC
  1997 defines `NO_EXPORT`'s boundary as the confederation boundary,
  explicitly noting a stand-alone AS not in a confederation is its own
  confederation — since this project has no confederation-member
  `PeerType` (see TODO.md's RFC 5065 gap), that boundary collapses to the
  plain AS boundary, identical to `NO_EXPORT_SUBCONFED`, for today's
  deployment shape. Documented explicitly rather than left as an
  unexplained coincidence.

7 new regression tests (v4 + v6) cover each community's suppression
behavior for both peer types, plus a route already advertised being
withdrawn once it starts carrying `NO_ADVERTISE` reactively. Real-teeth
verified: confirmed all 7 failed against the pre-fix code with the exact
expected assertion messages, confirmed all pass after the fix, then
mechanically reverted just the suppression guard and confirmed the same 7
failures reappeared before restoring.

A Codex review of GH PR #42 flagged that RFC 1997 is itself updated by
RFC 8642 (Policy Behavior for Well-Known BGP Communities), which governs
how a "set"/"add"/"delete community" policy directive should treat
well-known communities — relevant here since `is_export_suppressed()` is
checked *after* export policy mutates the route. Fetched RFC 8642 directly:
its only normative content is that a vendor's "set" directive behavior
toward well-known communities (implementations diverge — some strip them,
some preserve specific ones) MUST be documented and MUST NOT change once a
community becomes newly well-known. Documented `SetCommunities::apply()`'s
existing behavior (replaces the entire list unconditionally, matching the
Junos/Huawei/Brocade model) in `pathvector-policy/RFC.md`. Added 2 new
tests proving the suppression check's ordering is intentional, not an
implicit accident: a `NO_ADVERTISE` added by policy suppresses even when
absent from Loc-RIB, and a `NO_EXPORT` removed by policy lifts suppression
even when present in Loc-RIB. Real-teeth verified: both tests passed
immediately (the ordering was already correct); to confirm they have teeth,
temporarily switched the check to read pre-policy communities instead,
confirmed both failed with the expected messages, then restored.

A second Codex round on the same PR noted the ordering fix's coverage
exercised `AddCommunity`/`RemoveCommunity` but not `SetCommunities` —
the pre-existing `test_set_communities` only used ordinary values, so a
future well-known-preserving special case in `SetCommunities::apply()`
could pass every cited test while violating RFC 8642. Added
`test_set_communities_replaces_well_known_communities`
(`pathvector-policy/src/action.rs`), starting with `NO_EXPORT`/
`NO_ADVERTISE` present and asserting `set` replaces them too. Real-teeth
verified: temporarily patched `SetCommunities::apply()` to preserve
well-known communities across `set`, confirmed the new test failed while
the ordinary one stayed green, then restored.

---

## 2026-07-20 (RFC 7606 §5.2 missing-NLRI session reset — 3-layer fix)

### [pathvectord, pathvector-session] An UPDATE with attributes but no reachable NLRI was silently accepted instead of resetting the session

A Codex review of already-merged PR #31 (the RFC 7606 §3(d) missing-mandatory-
attribute fix, below) found a gap: `handle_update`'s mandatory-attribute check
only ran when the message had at least one recognized announced NLRI. An
UPDATE carrying path attributes (e.g. AS_PATH but no ORIGIN) with no
traditional NLRI, no MP_REACH_NLRI, and no MP_UNREACH_NLRI bypassed the check
entirely and was silently accepted as a no-op — neither treated-as-withdraw
nor session-reset. RFC 7606 §5.2 ("Missing NLRI") is explicit that this
message shape can't be confidently treated-as-withdraw (there's no reliable
NLRI to withdraw), so an attribute error here — one that would otherwise
resolve via treat-as-withdraw per §3(d) — must instead reset the session.

Fixing this correctly took four rounds, each surfacing a deeper layer of the
same underlying gap (`fix/rfc7606-missing-nlri-session-reset`, PR #41):

1. **Daemon layer** (`pathvectord/src/daemon/route.rs`): added the §5.2
   escalation — an UPDATE with no reachable NLRI but an attribute other than
   MP_UNREACH_NLRI, plus a missing ORIGIN/AS_PATH, now returns a
   `MissingWellKnownAttribute` NOTIFICATION and resets the session. The two
   legitimate NLRI-less encodings (a fully empty legacy End-of-RIB, an
   MP_UNREACH_NLRI-only End-of-RIB) remain unaffected.
2. **Transport layer** (`pathvector-session/src/transport/mod.rs`): the same
   escalation was missing in `handle_malformed_update`, where a *decode-time*
   attribute error (e.g. a malformed NEXT_HOP, not merely an absent one) on an
   NLRI-less message was forwarded as an ordinary treat-as-withdraw before the
   daemon ever saw it. Added `is_nlri_less_with_attributes`, applied to the
   *original* pre-transform UPDATE, gating the same escalation.
3. **Stripped-attribute blindness**: that same predicate only inspected the
   already-cleaned attribute list — the decoder removes a malformed attribute
   before `MalformedUpdate` is built, so a message whose *only* attribute was
   a malformed NEXT_HOP had an empty attribute list, indistinguishable from a
   legitimate empty End-of-RIB. Fixed by also consulting the decoder's
   per-attribute error list for attributes that didn't survive.
4. **AFI/SAFI conflation** (daemon layer again): the "no reachable NLRI" check
   conflated "did this daemon install anything locally" with "does the wire
   message have reachable NLRI" — a valid MP_REACH_NLRI for an AFI/SAFI this
   daemon doesn't support (e.g. IPv4 multicast) was silently skipped and never
   counted, wrongly triggering a session reset for a message that plainly
   does encode reachable NLRI. Added a wire-level reachability check
   independent of local AFI/SAFI support.

Each round shipped with a regression test real-teeth verified against the
specific bypass it closed (reverted, confirmed the exact pre-fix symptom,
restored, confirmed passing) before commit. Full workspace suite, clippy
`-D warnings`, and fmt clean at every step; all 7 CI checks (including E2E
Docker and fuzz) green on the final commit.

## 2026-07-20 (RFC 4271 §6.8 collision-identity validation — 4-round fix)

### [pathvector-session] Reversed-pair identity, OpenSent deferral, staging-context preservation, and operator-teardown eviction

Codex's review of already-merged PR #30 (the collision-resolution inversion
fix, below) surfaced that the fix's `ConnectionOrigin`-only tracking wasn't
sufficient proof of a genuine RFC 4271 §6.8 "reversed pair" — two connections
where one side dialed the other's listening port and vice versa. Closing this
took four rounds on `fix/rfc4271-collision-identity-validation` (PR #40):

1. **Reversed-pair identity check.** `TcpStream::local_addr()`/`peer_addr()`
   report "my end"/"their end" symmetrically regardless of which side dialed
   — not RFC 4271's packet-direction-based source/destination. Added
   `ConnectionIdentity { local, peer, origin }`, requiring same-local,
   same-peer, *and* opposite-origin — all three independently necessary (same
   endpoints alone also matches two inbound connections from the same peer;
   opposite origin alone also matches a multihomed speaker's unrelated
   connections). A first attempt at the endpoint comparison had the fields
   backwards ("crossed" instead of same-local/same-peer) — caught via manual
   derivation before it shipped.
2. **OpenSent premature adoption.** A candidate connection validating while
   the primary session is still `OpenSent` (its own peer identity not yet
   known) was being adopted immediately, guessing rather than deferring — RFC
   4271 §6.8 doesn't sanction examining an `OpenSent` connection without an
   out-of-band identity source, which this codebase doesn't have. Fixed by
   deferring the decision until the primary's own OPEN arrives (or it dies).
3. **Staging-context preservation.** The deferred-candidate mechanism
   re-derived "why was this candidate staged" from the primary's *current*
   state at resolution time — so a candidate staged as a §6.8 collision
   candidate could be reinterpreted as an RFC 4724 §4.2 GR reconnect if the
   primary reached `Established`+GR while the candidate was still pending,
   displacing a healthy primary. Fixed by recording the staging purpose
   (`CollisionPurpose::Collision` vs `GracefulRestart`) at staging time and
   gating every branch on that recorded purpose instead.
4. **Operator-teardown eviction.** `State::Idle` alone can't distinguish a
   genuine primary failure from a deliberate `ManualStop` or `NotificationToSend`
   teardown (RFC 9003 peer removal, etc.) — both land in `Idle` from
   `OpenConfirm`. A pending candidate could survive an operator-issued
   teardown and be silently adopted afterward, reopening a session the
   operator explicitly closed. Fixed by evicting any pending candidate
   outright the moment `run()` processes either input.

Every round shipped with real-teeth-verified regression tests (reverted,
confirmed the exact pre-fix symptom, restored, confirmed passing). Full
workspace suite, clippy, and fmt clean at every step; all 7 CI checks green
on the final commit.

## 2026-07-19 (RFC 6811 origin-ASN confederation-segment derivation)

### [pathvector-types, pathvector-policy, pathvectord] `AsPath::origin_as()` now applies RFC 6811 §2's confederation-segment substitution rule, and fixes a ROV bypass for terminal `AS_SET` paths

`fix/rfc6811-origin-as-confederation-segments` (PR #39). RFC 6811 §2 defines a
specific three-way rule for the ASN used in Route Origin Validation lookups:
an AS_PATH ending in a plain `Sequence` segment uses its rightmost ASN; one
ending in `ConfedSequence`/`ConfedSet` (or an empty path) substitutes the
*local speaker's own AS number*; any other final segment type (a terminal
`AS_SET`) yields RFC 6811's distinguished "NONE" sentinel. `AsPath::origin_as()`
instead searched backward past confederation/Set segments for the nearest
earlier plain `Sequence` — a materially different ASN could end up checked
against the VRP database in a confederation deployment, flipping a
Valid/Invalid/NotFound verdict incorrectly. Fixed by matching directly on the
path's final segment instead of searching backward; `origin_as()` now takes
`local_as: Asn`, threaded through its one production caller
(`RoaValidityCondition`) from `pathvectord`'s daemon state. Two tests that had
actively codified the old (wrong) backward-search behavior as correct were
rewritten with RFC-derived expectations, real-teeth verified against the
pre-fix code.

**Codex's review of the same PR found a second, more serious gap**: RFC
6811's "NONE" sentinel means "cannot be Matched by any VRP" — not "exempt
from validation." `RoaValidityCondition::matches` had been short-circuiting
to `false` (no match) whenever `origin_as()` returned `None`, which silently
let a *covered-but-unmatchable* route (AS_PATH ending in a plain `AS_SET`)
bypass a `reject Invalid` policy entirely, rather than correctly resolving to
`Invalid` per the RFC's own definition. Fixed by following RFC 6811 §2's own
pseudo-code, which represents "NONE" as ASN 0 — `matches` now feeds
`origin_as(local_as).map_or(0, Asn::as_u32)` into the existing covering-walk
in `RoaTable::validate`, which naturally produces `Invalid` (covered) or
`NotFound` (uncovered) instead of a silent non-match; `RoaTable::validate`
also gained an explicit `asn != 0` guard mirroring the RFC pseudo-code's own
check. Two new tests prove both the covered (`Invalid`) and uncovered
(`NotFound`) cases, real-teeth verified against the pre-fix short-circuit.

### [pathvector-rpki] RTR Error Code 2 ("No Data Available") no longer torn down like the 8 genuinely fatal error codes — took four Codex-review rounds to get right

`fix/rfc8210-error-code-2-no-data-available` (PR #38). RFC 8210 §12 marks
Error Code 2 as the one *non-fatal* RTR error — a transient "cache still
rebuilding" signal that should keep the session alive and retry, not tear the
whole RTR connection down like the other 8 codes. The initial fix added a
dedicated retry-in-place arm, but three successive Codex review passes each
found a real remaining bug: (1) a code-2 response to a routine *Serial* Query
should force the *next* query to be a genuine Reset Query per §8.4 ("issue
periodic Reset Queries until it gets a new usable load"), not a repeat Serial
Query, since `sync_once` otherwise just recomputes and resends the same query
type it already had; (2) the fix for that then cleared the ROA table
*eagerly* on receiving Error Code 2, discarding the last known-good data for
the entire (potentially long) retry window — RFC 8210's own stale-data
philosophy explicitly prefers stale data to no data, so the clear was moved
to fire only once the forced Reset Query's `CacheResponse` actually arrives;
(3) the regression test proving the "stale data survives the retry window"
property used an unsynchronized poll loop that could pass trivially against
data from *before* Error Code 2 was ever sent, proving nothing — fixed with a
`oneshot` handshake pinning the assertion to a moment provably inside the
retry window. Also added `RtrStatus::last_error` tracking and threaded the
cache's own advertised Retry Interval (RFC 8210 §6) into the retry cadence,
replacing a flat config default. Each of the four rounds shipped with a
regression test real-teeth verified against the specific bug it closed.

## 2026-07-18 (RFC 4271 best-path tie-break, LOCAL_PREF eBGP filtering, GR/Role capability duplicates)

### [pathvector-rib, pathvectord] Best-path tie-break steps (f) BGP Identifier and (g) peer address were conflated into one peer-IP-only comparison

`fix/rfc4271-bestpath-tiebreak-f-g` (PR #37). RFC 4271 §9.1.2.2's final two
tie-break criteria are two *distinct* values — a router's BGP Identifier is
commonly a loopback address unrelated to its session/peer IP — but
`best_path.rs`'s tie-break skipped Identifier comparison entirely and used
peer-IP for both steps, silently diverging from the RFC whenever a route's
BGP-Identifier ordering and peer-IP ordering disagreed. Added
`Route::peer_bgp_id`, populated at UPDATE-ingest time from the daemon's
existing per-peer BGP-ID tracking (already maintained for ORIGINATOR_ID
fallback), and a real step (f) comparing it ahead of the renamed step (g)
peer-IP fallback (used when either side's Identifier is unknown, e.g. locally
originated routes). Also corrected a mislabeled `pathvector-rib/RFC.md` row
that had claimed a peer-IP test was proving BGP-Identifier comparison — split
into two accurate rows. Real-teeth verified at both the isolated-comparator
level (unit + proptest) and the daemon-wiring level (a dedicated test proving
`handle_update` actually threads the established peer's BGP ID onto the
route, not just that the comparator works on hand-built fixtures).

### [pathvectord] LOCAL_PREF received from an eBGP peer is no longer honored — the audit's highest-severity RFC 4271 finding

`fix/rfc4271-local-pref-ebgp-ignore` (PR #35). RFC 4271 §5.1.5 requires
LOCAL_PREF from an external peer to be ignored — specifically so an eBGP peer
can't manipulate this router's best-path selection. `handle_update` captured
`LocalPref` with no peer-type check, letting a malicious or misconfigured
eBGP peer send an arbitrary value (e.g. `u32::MAX`) to force its route to win
the very first best-path tie-break step against routes this router would
otherwise prefer. Fixed by gating the capture on `peer_type == Internal`; from
any other peer type the attribute is now silently dropped rather than
substituted. Three new tests prove the gate itself (both directions) and the
actual security property end-to-end (a bogus-LOCAL_PREF, longer-AS_PATH eBGP
route no longer beats a shorter-AS_PATH one once the bogus value can't
short-circuit the comparison). Also proven over a real wire-level session via
`pathvector-e2e`'s `mock_bgp_fault_peer`. The RFC's confederation exception to
this rule is deliberately not handled — this daemon has no confederation-aware
peer classification yet, tracked as its own larger initiative.

### [pathvector-session] Duplicate GracefulRestart capability instances used first-nonzero, not last; peer-side duplicate/conflicting Role Capabilities went undetected

`fix/rfc4724-rfc9234-capability-duplicates` (PR #36). Two instances of the
same "first-wins instead of RFC-mandated last-wins" bug shape, found in the
same audit pass:

- RFC 4724 §3 requires the *last* GracefulRestart capability instance to win
  if a peer sends 2+. The existing code searched for "the first instance with
  `restart_time > 0`" — so a peer sending `[restart_time=120, restart_time=0]`
  incorrectly kept the earlier 120 instead of reaching the true (authoritative,
  EOR-only) last instance. Fixed with a dedicated `extract_gr_capability()`
  that finds the actual last instance first, then interprets it.
- RFC 9234 §4.2 requires rejecting a connection (Role Mismatch) if a peer
  sends 2+ Role Capabilities with *differing* values — `validate_open` took
  only the first via `find_map`, so a peer sending `[Customer, Peer]` against
  a compatible-with-`Customer` local role proceeded to `OpenConfirm` without
  ever noticing the conflicting second value. Fixed by collecting every Role
  value the peer sent and rejecting immediately if they're not all identical.

Both fixes shipped with tests written first and confirmed to fail against the
unfixed code with clear diagnostics before the fix landed.

## 2026-07-17 (RFC 7606 attribute-flags/OTC/truncation cluster)

### [pathvector-session] Attribute Flags conflicts were never checked; a malformed OTC evaded RFC 9234 leak detection; five fixed-length attributes silently truncated instead of erroring

`fix/rfc7606-attribute-flags-cluster` (PR #34), closing out several related
findings from the same audit pass:

- RFC 4271 §4.3's Attribute Flags requirement (Transitive bit MUST be 1 for
  well-known attributes; Partial bit MUST be 0 for well-known/optional-
  non-transitive) was decoded off the wire but never checked against what
  each known attribute type is supposed to have.
- OTC (RFC 9234's route-leak detection mechanism) fell into the generic
  attribute-discard policy for a malformed-length value instead of RFC
  9234 §5's mandated treat-as-withdraw — a plausible leak-detection evasion
  path, since a route that should be caught by `OtcLeakCondition` could
  instead pass through untagged if its OTC attribute were deliberately
  malformed.
- ATOMIC_AGGREGATE had no length check at all (should be exactly 0).
- ORIGIN, NEXT_HOP, MED, LOCAL_PREF, and AS4_AGGREGATOR all used a
  too-short-only length check (`< N` instead of `!= N`), so a value declared
  longer than its correct fixed size had its excess bytes silently discarded
  with no error — found live while fixing the ATOMIC_AGGREGATE gap, not part
  of the original audit pass.

All fixed by moving OTC into the `TreatAsWithdraw` policy arm and correcting
the five truncation checks to exact-length. Real-teeth verified individually
per attribute; also proven over a real wire-level session via
`pathvector-e2e`'s `mock_bgp_fault_peer` (`malformed-otc` scenario).
AGGREGATOR's own length-vs-negotiated-4-octet-ASN-capability gap was
deliberately deferred as its own follow-up ("PR 4b" in the roadmap).

### [pathvector-e2e] Satisfy `clippy::similar_names` in test helpers without an `-A` override

`fix/clippy-similar-names-e2e` (PR #33). Housekeeping: renamed several
similarly-named IP/ID test-helper bindings in `pathvector-e2e/src/lib.rs` so
the lint passes on its own merits rather than being suppressed.

### [pathvector-session] Duplicate MP_REACH_NLRI/MP_UNREACH_NLRI now correctly forces a session reset; every other duplicated attribute is silently normalized, not withdrawn

`fix/rfc7606-duplicate-attribute-handling` (PR #32). RFC 7606 §3(g)/(h)
requires two different, opposite-direction behaviors for a duplicated
attribute depending on type: a duplicated MP_REACH_NLRI/MP_UNREACH_NLRI needs
a full session reset (stronger than the codebase's prior treat-as-withdraw for
everything); any other duplicated attribute should be silently normalized —
keep the first, drop the rest, no error at all (weaker than the prior
blanket treat-as-withdraw, which wrongly withdrew the whole route for an
ordinary duplicate like two COMMUNITY attributes). Fixed by branching on type
code in the decoder and adding a `session_reset` flag alongside the existing
`treat_as_withdraw`, with §3(h)'s "strongest action wins" rule applied where
both can independently be true for the same UPDATE.

**Two rounds of Codex review then found real bugs in the fix itself**: the
session-reset path was recording the wrong `TerminationReason` (`Unclean`
instead of `OperatorStop`), which would have wrongly triggered RFC 4724 GR
helper-mode route retention for what's actually a deliberate, locally
detected protocol-error teardown — fixed by routing through the FSM's
existing `NotificationToSend` input, which already maps to `OperatorStop`.
The fix for *that* then left a still-configured peer stuck in `Idle` forever
with no reconnect, since `NotificationToSend`'s existing semantics
deliberately omit the connect-retry timer (correct for its other two
call sites, RFC 9003 shutdown and max-prefix-exceeded, but wrong for an
ordinary protocol error a peer might recover from) — fixed by adding a new,
narrowly-scoped `FsmInput::ProtocolErrorNotificationToSend` per RFC 4271
§8.2.2 Event 28, identical to `NotificationToSend` plus the retry timer. All
three rounds real-teeth verified; also proven over a real wire-level session
via `pathvector-e2e`'s `mock_bgp_fault_peer` (`duplicate-mp-reach` scenario),
whose own e2e test needed two further fixes (a keepalive loop so the
session's own hold timer couldn't confound the assertion, and an
Established-confirmation wait) before it was a reliable real-teeth signal.

## 2026-07-16/17 (RFC 4271 §6.8 collision resolution, RFC 4724 GR override, RFC 7606 missing-mandatory-attribute)

### [pathvector-session] BGP connection-collision resolution had its BGP-ID comparison backwards; RFC 4724 GR restart wasn't recognized during collision; both missing the RFC-required NOTIFICATION

`fix/rfc4271-collision-resolution` (PR #30). `handle_incoming_connection`'s
collision comparison (`should_close_outbound = local_bgp_id > peer_id`) was
inverted relative to RFC 4271 §6.8, which retains the connection *initiated
by* the higher-ID speaker. Self-consistent when two instances of this same
daemon collide with each other (both invert the same way and still converge),
but against any standards-compliant peer in a genuine simultaneous-connect
race, each side would compute a different required survivor and close the
connection the other side was trying to keep — potentially preventing the
session from ever establishing in that race window. The existing test asserting
this behavior had locked in the inverted outcome as correct. Also found in the
same pass: neither collision-detection FSM arm sent the RFC-required
Cease/ConnectionCollisionResolution NOTIFICATION before closing.

Same branch also fixed a related RFC 4724 §5 gap: an incoming connection
arriving while the session is `Established` with GR negotiated is supposed to
be recognized as evidence the peer restarted (retain its routes, drop the old
connection) rather than rejected as an ordinary collision — the
`Established`-state handler didn't check GR status at all.

Proven both at unit level and against a real, separately-built Docker image
via a new `mock_bgp_collision_peer` e2e test double (two real TCP connections
forcing each direction of the comparison, plus a route-retention check across
the GR-override switchover), each real-teeth verified by reverting the
specific fix, rebuilding the image, and confirming the corresponding test
fails before restoring. (This area went on to need a further four rounds of
identity-validation hardening after a later Codex review — see the
2026-07-20 entry above.)

### [pathvectord] A missing well-known mandatory attribute (ORIGIN/AS_PATH/NEXT_HOP) was tearing down the whole session instead of withdrawing just that route

`fix/rfc7606-missing-mandatory-attribute` (PR #31) — the highest-priority
finding of the whole audit pass, since it's triggerable by an entirely
ordinary condition (any peer's UPDATE encoding quirk that happens to omit
ORIGIN or AS_PATH once) rather than a rare race or a peer willing to send a
deliberately bogus value. RFC 7606 §3(d) explicitly revises RFC 4271 §6.3:
"treat-as-withdraw MUST be used," not session reset. `handle_update` sent a
`MissingWellKnownAttribute` NOTIFICATION and reset the session instead. Fixed
by withdrawing the affected route (Adj-RIB-In and LocRib, both IPv4 and the
initially-uncovered IPv6/MP_REACH_NLRI path) instead of returning a
NOTIFICATION; every sibling test asserting the old session-reset behavior was
rewritten, not just the misleadingly-named one that first surfaced the gap.
Proven at the wire level via `pathvector-e2e`'s `mock_bgp_fault_peer`
(`missing-origin` scenario), real-teeth verified by reverting the fix,
rebuilding the actual Docker image, and confirming the test fails first.
(This area went on to need a further four rounds of missing-NLRI hardening
after a later Codex review — see the 2026-07-20 entry above.)

## 2026-07-16 (adversarial input / fault-injection testing)

### [pathvector-session, pathvector-e2e] Close the chaos/adversarial testing gap, fix two real bugs found along the way

TODO.md's Tier 3 item 11 ("Adversarial input / NOTIFICATION path testing") was
blocked on RFC 7606, which shipped earlier. With that prerequisite in place,
added `pathvector-e2e/tests/fault_injection.rs`: 6 scenarios driven by a new
adversarial test double, `mock_bgp_fault_peer` (see
`pathvector-e2e/src/bin/mock_bgp_fault_peer.rs`), against a real running
pathvectord — corrupted BGP header (bad marker/length/type), truncated bytes
during the OPEN exchange (both held-open and closed-immediately variants), a
malformed UPDATE (invalid ORIGIN, RFC 7606 treat-as-withdraw), and a
mid-session TCP reset via `disconnect_gobgp`/`reconnect_gobgp`. Every scenario
asserts a GoBGP **control** peer's session stays healthy throughout — proving
a fault on one connection can't wedge the rest of the daemon (each peer's
session runs on its own independent `tokio::spawn`ed task).

Writing these tests surfaced two real, previously-unnoticed bugs in
`pathvector-session`, not just gaps in test coverage:

- **RFC 4271 §6.1 non-compliance.** A corrupted header (bad marker, bad
  length, or an unrecognized message type) was silently dropping the TCP
  connection instead of sending the RFC-mandated NOTIFICATION first —
  `transport/mod.rs`'s `recv_message` error arm treated a framing-layer
  `CodecError` identically to a real TCP failure. Fixed by mapping
  `CodecError::InvalidMarker`/`InvalidLength`/`UnknownMessageType` to the
  correct `NotificationError::MessageHeader` subcode (with the erroneous
  length/type byte in the NOTIFICATION's `data` field, per RFC 4271 §6.1) and
  sending it before tearing down. Non-header `CodecError` variants (malformed
  OPEN/NOTIFICATION bodies) remain unmapped — tracked as a follow-up in
  TODO.md.
- **FSM bug: a silently-partitioned peer never reconnected.** All three FSM
  states that handle `HoldTimerExpired` (OpenSent, OpenConfirm, Established)
  omitted `FsmOutput::StartConnectRetryTimer` from their output list — present
  in the sibling `TcpFailed`/NOTIFICATION-received arms, but missing here. A
  `docker network disconnect` produces no TCP-level error (no RST, no read
  failure — packets just stop being delivered), so pathvectord only notices
  via hold-timer expiry, not a socket error. That left the session stuck in
  `Idle` forever, with zero further connection attempts — confirmed directly
  via `ss -tn` inside the container showing no outbound activity at all,
  requiring a full daemon restart or peer removal/re-add to recover in
  production. The existing `test_hold_timer_expired_in_open_sent` /
  `_in_open_confirm` / `_in_established` unit tests never asserted on the
  retry timer, which is why this went unnoticed; all three now do, and the
  e2e `mid_session_tcp_reset_recovers_cleanly` test exercises the real-world
  path end-to-end.

See `pathvector-session/RFC.md`'s new RFC 4271 §6.1 section and the updated
§8 FSM table for the exact requirements and verifying tests.

---

## 2026-07-06 (metrics: FIB write failures, originated-route count, import-policy rejects)

### [pathvectord] Close three more Prometheus observability gaps surfaced by BlockingArbiter-RS

Reviewing the 2026-07-05 metrics work raised a broader question: does
pathvectord's `/metrics` endpoint actually expose the daemon's inner
RIB/FIB/policy state, not just per-peer session status? A grep for every
`crate::metrics::` call site showed three whole subsystems had zero
instrumentation — confirmed against a real downstream consumer,
BlockingArbiter-RS, whose own TODO documents a live gap this closes: its
`desired_bgp_delta` health check has no way to cross-check pathvectord's
actual reported state against its own internal bookkeeping.

- **No visibility into kernel FIB write outcomes.** `fib::process_batch`
  logged a `tracing::warn!` on a failed kernel write but exposed nothing to
  Prometheus — an operator had to grep daemon logs to notice the kernel was
  rejecting routes. Added `pathvectord_bgp_fib_write_failures_total{afi, op}`
  (`op` ∈ `install`/`blackhole`/`withdraw`/`withdraw_blackhole`) and
  `pathvectord_bgp_fib_routes_installed{afi}`, the ground-truth counterpart to
  `loc_rib_prefixes{afi}` — persistent divergence between the two is itself a
  signal that the kernel isn't converging with Loc-RIB. The gauge only moves
  on a successful write; a failure leaves it untouched and increments the
  counter instead, so the two never move together.
- **No visibility into self-originated route count.** Origination bypasses
  import policy by design, but pathvectord never exposed how many routes it
  currently self-originates. Added `pathvectord_bgp_originated_routes{afi}`,
  set from `rib.originated_routes.len()`/`originated_routes_v6.len()` after
  every origination/withdrawal batch, and pre-set to `(0, 0)` at startup.
- **No visibility into import-policy rejections.** Added
  `pathvectord_bgp_import_policy_rejected_total{peer}`, incremented only for
  routes where `Policy::evaluate` returns `Decision::Reject`/`Decision::Next`.
  Deliberately excludes RFC 7999 BLACKHOLE-community routes (diverted to a
  kernel null route before policy ever runs) and RFC 4271 transport-level
  drops (invalid NEXT_HOP, AS-path loop) — both increment the existing
  `rejected`/`rejected_v6` counters used for the daemon's own log line, but
  counting them here would make policy look like it's rejecting routes it
  never even evaluated. `handle_update` tracks a separate
  `policy_rejected`/`policy_rejected_v6` counter to keep this distinction
  correct; a regression test sending an all-BLACKHOLE UPDATE guards against
  the two being conflated again. `reapply_import_policy`/`_v6` (full Adj-RIB-In
  re-evaluation on policy reload or RPKI ROA cache update) also feed this
  counter — a spike from that path means "this many routes are currently
  rejected under the re-evaluated policy," not "this many new rejections just
  happened," since the whole table is re-scored at once.

**Deferred:** export-side policy rejects (would need the same
wide-call-site + enum restructuring already deferred once for
`updates_sent_total`, plus `PrefixDecision`'s variants don't yet distinguish
"policy rejected" from other withdraw causes), a granular per-reason label for
import-policy rejects (blocked on `Decision` carrying no information about
which condition fired), and external reconciliation for
`fib_routes_installed` (a silent kernel-side failure that never surfaces as
an `Err` would drift the gauge with no self-correction — would need a
periodic netlink route-table diff pass).

---

## 2026-07-05 (metrics: fix stale adj_rib_out, add updates_sent counter, pre-register peers)

### [pathvectord] Close three Prometheus observability gaps surfaced by real downstream usage

Found using pathvectord from BlockingArbiter-RS (a project consuming the daemon's
published Docker image): Grafana panels showed nothing for a peer until route churn
happened to touch it, and there was no way to graph outbound UPDATE activity at all.

- **`adj_rib_out_prefixes` could stay stale after Established.** `update_rib_sizes`
  previously only fired from route-update/flush call sites — a peer that reached
  Established but then saw no further route churn from *anyone* could sit with a
  stale or missing outbound gauge indefinitely. Fixed by calling `update_rib_sizes`
  immediately after `on_established` (`daemon/mod.rs`), which is safe because
  `on_established` already calls `sync_advertised(peer_ip)` synchronously after the
  full-table dump and EOR send completes.
- **No outbound UPDATE counter.** `pathvectord_bgp_updates_received_total{peer}`
  existed but had no outbound counterpart — `adj_rib_out_prefixes` is a point-in-time
  gauge, so a withdraw immediately followed by a re-announce was invisible as churn.
  Added `pathvectord_bgp_updates_sent_total{peer}`, incremented once per real UPDATE
  message (not once per `flush_updates`/`flush_updates_v6` call — a batch that splits
  into several wire messages increments once per message, verified by a dedicated
  test that counts actual channel sends and asserts the counter matches).
- **No metrics at all for a peer that never establishes.** Every peer-labeled gauge
  was created lazily on its first Established/Terminated/route-update event, so a
  misconfigured or unreachable peer — the case an operator most needs visibility
  into — had no series whatsoever, indistinguishable from an unconfigured peer on a
  dashboard. Added `register_peer`, which pre-creates `session_up`/
  `adj_rib_in_prefixes`/`adj_rib_out_prefixes` at zero; called for every
  statically-configured peer at startup (after the metrics endpoint installs) and
  from the dynamic-peer `AddPeer` handler, before that peer's session task is
  spawned.
- **No Loc-RIB size at all until the first peer event.** `pathvectord_bgp_loc_rib_prefixes{afi}`
  (a global, non-per-peer gauge) is only set by `update_rib_sizes`, which is only
  called from event-driven sites (post-Established, post-flush) — a daemon with
  zero established peers showed no Loc-RIB size at all, not a real `0`. Fixed by
  calling `update_rib_sizes(0, 0, &HashMap::new())` right after the metrics
  endpoint installs at startup, alongside `register_peer`'s loop.

---

## 2026-07-05 (release: fix aarch64-unknown-linux-musl binary build)

### [ci] `cross`'s aarch64-musl release build was compiling against a stale `protoc`

The `v0.1.0` release run's `aarch64-unknown-linux-musl` job failed at
`pathvectord`'s build script with `protoc failed: ... Explicit 'optional'
labels are disallowed in the Proto3 syntax` — not a defect in
`management.proto` (its `optional` fields are deliberate; prost maps them to
`Option<T>` for real presence-tracking on fields like `local_pref`/`med`/
`aggregator`, and proto3 `optional` support has been standard since protoc
3.15, 2021). The actual cause: `Cross.toml`'s `pre-build` hook installed
`protoc` via `apt-get install protobuf-compiler`, and the `cross` tool's
`aarch64-unknown-linux-musl` base image is old enough that its apt repo only
has a pre-3.15 protoc. The native `x86_64-unknown-linux-musl` release job
(no `cross`, runs directly on `ubuntu-latest`) was unaffected since that
runner's apt repo has a modern protoc.

Fixed by pinning a specific upstream protoc release (v35.1) downloaded
directly in the `pre-build` hook instead of relying on the container's apt
package. Verified the actual root cause directly: running protoc v35.1
against `management.proto` compiles cleanly with zero errors (confirmed
locally via `PROTOC=<v35.1 binary> cargo build --release -p pathvectord`).
A full local `cross build --target aarch64-unknown-linux-musl` could not be
reproduced end-to-end on Apple Silicon — `cross`'s base image for that
target has no `arm64` manifest variant, an unrelated limitation of running
`cross` locally on an M-series Mac, not something that affects CI (which
runs on an x86_64 GitHub runner where that image resolves natively).

---

## 2026-07-05 (e2e CI: fix flaky port race, cut Docker build time ~4x)

### [pathvector-e2e] [ci] Two CI reliability/speed fixes surfaced by the IPv6 migration's CI run

- **Flaky port allocation.** `alloc_free_port()` (used by every harness to
  pick a host port for pathvectord's mapped gRPC port) asks the OS for a
  free ephemeral port, then releases it before Docker actually binds the
  same port number — a documented, accepted TOCTOU race. Under CI's 4-way
  test parallelism the gap between "OS says this port is free" and "Docker
  binds it" (which can span an entire peer container's startup + healthcheck
  wait) occasionally lets two tests get handed the same port, failing one
  with "port is already allocated". Added `.config/nextest.toml` with a
  `package(pathvector-e2e)`-scoped retry override (2 retries) so this class
  of transient infra flake self-heals; every other crate stays at 0 retries
  so a real regression still fails immediately.
- **Redundant Docker compiles.** `Dockerfile.pathvectord`,
  `Dockerfile.mock-rtr`, `Dockerfile.mock-bgp-peer`, and
  `Dockerfile.mock-bgp-dialer` each independently ran their own
  `cargo build -p X` against the full ~15-crate workspace from a cold
  `rust:1.88-slim-bookworm` base — up to 4x redundant compilation of the
  same dependency graph, since three of the four binaries live in
  `pathvector-e2e` itself. Merged into one `Dockerfile.pathvectord` with a
  shared `builder` stage that compiles all four binaries in a single
  `cargo build` invocation, plus four thin named final stages
  (`pathvectord`, `mock-rtr`, `mock-bgp-peer`, `mock-bgp-dialer`) each
  copying their own binary out. `docker build` with no `--target` still
  resolves to the `pathvectord` stage (used unchanged by
  `.github/workflows/publish.yml`'s release build); the three mock images
  now require an explicit `--target`. Local verification: first image
  (`pathvectord`) built in ~45s (full compile); the three mock images that
  follow it built in ~1.3–1.5s each (reusing the cached builder layer)
  instead of a full recompile — confirmed all four resulting images are
  functionally correct by re-running `rpki.rs`, `role.rs`, and
  `ipv6_accept.rs` (the tests that exercise mock-rtr, mock-bgp-peer, and
  mock-bgp-dialer respectively) against the freshly-built images.

---

## 2026-07-05 (IPv6 migration: close remaining confidence gaps)

### [pathvectord] [pathvector-e2e] Prove the IPv6 peer-identity migration end to end, not just by absence of a `V4`/`V6` branch

The IPv6 BGP transport migration below shipped with every e2e test still
configuring the peer as passive (pathvectord always dials), so the daemon's
listener had only ever accepted IPv4-sourced connections in practice, and no
test constructed a peer whose *identity* was a genuine `Ipv6Addr` rather than
an `Ipv4Addr`-shaped literal typed `IpAddr`. This closes both gaps, plus two
smaller ones surfaced by the same review.

- **Accept path**: new `pathvector-e2e/src/bin/mock_bgp_dialer.rs` and
  `Ipv6AcceptHarness` configure pathvectord's own outbound dial to an
  unreachable port while the dialer's inbound connection uses a
  `docker run --ip6`-assigned static address, so the only way the session in
  `pathvector-e2e/tests/ipv6_accept.rs`
  (`session_establishes_over_ipv6_accept_path`) can reach Established is
  through pathvectord's listener accepting a real inbound IPv6 connection —
  the dial path is structurally disabled, not just unused.
- **v6-identified peer**: `test_ipv6_peer_identity` in
  `pathvectord/src/daemon/mod.rs` drives a peer keyed by a real `Ipv6Addr`
  through route acceptance/propagation, export-policy enforcement, and
  RFC 4724 GR stale-route retention on unclean termination — the combination
  no prior test exercised.
- **ORIGINATOR_ID fallback regression**: the migration changed the RR
  ORIGINATOR_ID-injection fallback from `peer_ip` to
  `self.rib.local_bgp_id` (`peer_ip` could now be IPv6, which isn't a valid
  4-byte BGP Identifier). `test_rr_originator_id_falls_back_to_local_bgp_id_when_peer_bgp_id_unknown`
  proves this directly.
- **Flakiness / regressions**: the full `pathvector-e2e` suite (20 test
  files) re-run clean (0 failures), and both new IPv6 e2e tests were run 4
  times each with no failures, beyond the single pass each got when the
  gap analysis first landed.

All four new/extended tests were verified to have real teeth — each was
confirmed to fail against a deliberately broken version of the code under
test before the fix was restored and re-verified passing.

---

## 2026-07-05 (native IPv6 BGP transport)

### [pathvectord] Peers can now be configured with an IPv6 transport address

Closes the `TODO.md` "IPv6 BGP transport" gap — distinct from IPv6 *NLRI*
(MP_REACH_NLRI over an IPv4 session), which already worked. `PeerConfig`,
`DaemonState`'s ~40 peer-identity-keyed collections (`RibSnapshot`,
`import_policies`/`export_policies`, capability/role maps, GR state,
stalled/pending-removal sets, prefix counters), `DaemonCommand::RemovePeer`,
and the gRPC `PeerService`/`PolicyService` handlers (`get_peer`, `add_peer`,
`remove_peer`, `soft_reset`, `set_import_default`, `set_export_default`,
the `list_routes`/`watch_routes` peer filter) all migrated from `Ipv4Addr` to
`IpAddr`. The BGP listener already binds both `0.0.0.0:<port>` and
`[::]:<port>` unconditionally (prior work); this closes the gap between that
listener and the rest of the daemon actually treating an IPv6 peer identity
correctly end to end.

`peer_bgp_ids`/`local_bgp_id`/ORIGINATOR_ID remain `Ipv4Addr` throughout —
the BGP Identifier is always 4 bytes regardless of transport family, per
RFC 4271/6286.

New e2e test `pathvector-e2e/tests/ipv6_transport.rs`
(`session_establishes_over_ipv6_transport`): pathvectord dials a GoBGP peer
at its routable (global-scope ULA) IPv6 address on a Docker `--ipv6` bridge
network and reaches Established over a real IPv6 TCP connection — the first
e2e test in this project where the BGP session's own transport is IPv6, not
just its NLRI payload. `get_peer`/`list_peers` correctly report the peer's
address back as IPv6.

Not in scope: MD5 authentication for IPv6 peers (`pathvector-sys`'s
`TcpMd5Sig` is `sockaddr_in`-based; tracked separately in `TODO.md`).

---

## 2026-07-04 (pathvectord event-loop proptest)

### [pathvectord] Close the "event-loop transitions have no proptests" gap

`TODO.md`'s testing-strategy notes flagged that `pathvectord`'s `DaemonState`
update/withdraw/originate methods had no property tests, unlike
`pathvector-rib`/`pathvector-session`/`pathvector-policy`, which all do.

Added `rib_consistency_prop_tests::prop_adj_rib_out_always_subset_of_loc_rib`
(`daemon/mod.rs`): drives a random sequence of up to 30 operations (peer
announce/withdraw over both IPv4 and IPv6, local originate/withdraw) against a
3-peer `DaemonState`, asserting after every single operation that every prefix
each peer's `AdjRibOut` (v4 and v6) is currently advertising is also present in
`LocRib`. `AdjRibOut` only ever holds routes derived from `LocRib`'s best path,
so this invariant must hold continuously — a violation means a peer is being
told about a route pathvectord itself no longer considers valid.

Verified the test has real teeth (not vacuously passing) by temporarily
disabling the `propagate_to_all_peers` call in `on_route_update` and
confirming the test fails and shrinks to a clean 3-operation minimal
reproduction, then restoring the real code and confirming it passes again.

---

## 2026-07-04 (mold linker in CI)

### [ci] Use mold as the linker in GitHub Actions to cut CI wall-clock time

CI runs (nextest + doctests + clippy + fmt + doc + MSRV + e2e Docker builds) were
taking 10-15+ minutes per push, driven mostly by the `Test`/`Lint`/`MSRV` jobs'
final link step and the e2e job's three Rust-compiling Docker image builds
(`pathvectord`, `mock_rtr_server`, `mock_bgp_peer`). Added `mold` (installed via
apt) as the linker for those jobs and Docker builds — Linux-only, via a
job-scoped `RUSTFLAGS` env var in `ci.yml` and `ENV RUSTFLAGS` in each affected
Dockerfile's builder stage. No committed `.cargo/config.toml`, so this has zero
effect on local development, which stays on whatever linker macOS/the
contributor's own machine already uses.

Verified locally first in a container matching CI's exact base image
(`rust:1.88-slim-bookworm`): confirmed via the linked binary's `.comment`
section that mold actually performed the link, not a silent fallback to the
default linker.

Measured on two real GitHub Actions runs on this PR, compared against the last
pre-mold `main` CI run:
- `Lint` and `MSRV` jobs: ~25% faster once `Swatinem/rust-cache` warmed up for
  the new `RUSTFLAGS` fingerprint (first run after the change is a cold
  rebuild — expected, since changing `RUSTFLAGS` invalidates that cache).
- e2e job's three Docker image builds: ~15-17% faster, consistent across
  the cold-rebuild run (~83s saved combined).
- e2e job's own `pathvector-e2e` compile (before the Docker-based tests run):
  reproduced consistently across both runs (193s, 195s) vs. 361s pre-mold —
  a real, repeatable win, not noise (testcontainers is a heavy compile-time
  dependency here per `CONTRIBUTING.md`).
- Total workflow wall-clock time: 16m15s (pre-mold baseline) → 4m52s on the
  second (cache-warm) run. Part of that drop is Docker's own layer cache
  reusing an unchanged image build (unrelated to mold — the second run was
  an empty commit, so nothing in the three Rust-compiling images actually
  needed rebuilding), so the honest, mold-attributable number is the
  Lint/MSRV/e2e-test-compile improvements above, not the full 3.3x headline
  figure.

## 2026-07-04 (IPv6 GR e2e coverage + two incidental fixes)

### [pathvector-e2e] Add missing IPv6 e2e coverage for GR deadline expiry and export-policy reject

The previous entry's fix (`on_gr_deadline_expired` IPv6 re-propagation) and the
export-policy IPv6 gap fix (2026-07-02) both shipped without an e2e test proving
they work over a real BGP session. Added `GrIpv6ObserverHarness`
(`pathvector-e2e/src/lib.rs`) — a three-container topology (GoBGP-source,
GoBGP-observer, pathvectord) — and two new tests:
`gr_deadline_expiry_sends_v6_withdrawal_to_observer`
(`tests/graceful_restart_ipv6.rs`) and
`export_default_reject_blocks_ipv6_propagation_to_peer` (`tests/policy.rs`).

GoBGP-observer uses a distinct AS (65003) rather than reusing GoBGP-source's AS
65001 — sharing an AS was tried first and produced a confusing failure where
pathvectord correctly re-advertised the route but GoBGP-observer's own AS_PATH
loop-prevention silently discarded it on receipt, since the AS_PATH already
contained 65001 from the originating hop (RFC 4271 §9.1.2 working as designed).

### [pathvectord] Fix `prefixes_advertised` staleness after IPv6-only propagation

Found while instrumenting the above e2e test: `propagate_to_all_peers_v6` never
called `sync_advertised` itself, relying on `propagate_to_all_peers` (the v4
path) to do it. Since the v4 call runs first and reads `adj_ribs_out_v6` before
`propagate_to_all_peers_v6` has a chance to mutate it, an UPDATE that only
carried IPv6 NLRIs left `prefixes_advertised` stale until an unrelated v4 event
happened to resync it. Fixed by adding the same sync loop to
`propagate_to_all_peers_v6`; regression test
`test_v6_only_propagation_syncs_prefixes_advertised`.

### [pathvector-e2e, pathvector-stress] Fix `cargo test`/`cargo nextest run` hanging on non-test-harness binaries

`mock_rtr_server`, `mock_bgp_peer` (`pathvector-e2e`), and `stress`
(`pathvector-stress`) are long-lived servers / load generators, not test
harnesses. Without an explicit `test = false`, Cargo treats every `[[bin]]`
(including auto-discovered `src/bin/*.rs` targets) as testable by default and
invokes the compiled binary with `--list --format terse` during test discovery.
None of these three understand that flag — their real `main` just runs
unconditionally, hanging the whole `nextest run`/`nextest list` phase
indefinitely with no error output. `pathvector` and `pathvector-mrt`'s bin
targets were left untouched — both have real `#[test]`s compiled through the
same harness and correctly handle `--list` today.

---

## 2026-07-03 (GR deadline IPv6 re-propagation)

### [pathvectord] `on_gr_deadline_expired` now re-propagates IPv6 withdrawals to other peers

Found while closing the IPv6 export-policy gap (previous entry): when a GR-capable
peer's restart window expires without re-establishment, `on_gr_deadline_expired`
(`src/daemon/gr.rs`) correctly withdrew both v4 and v6 routes from the kernel FIB
and this daemon's own Loc-RIB, but the loop that notifies *other* BGP peers of the
withdrawal only iterated IPv4 prefixes and called `propagate_prefix`. Other peers
never received a BGP WITHDRAW for IPv6 routes that were only reachable via the
expired peer — they kept believing those routes were still valid until their own
hold timer or a future full update corrected it, even though the kernel FIB and
Loc-RIB were already correct.

Fixed by capturing `prev_prefixes_v6` (mirroring the existing `prev_prefixes`
snapshot-before-withdraw pattern) and adding a second re-propagation loop over
IPv6-capable peers that calls `propagate_prefix_v6` with each peer's
`export_policies_v6` entry, mirroring `prune_stale_nlri_v6`'s existing shape
(the EOR-prune path, which already had this). New regression test
`deadline_expiry_propagates_v6_withdrawal_to_observer` mirrors the existing v4
test `deadline_expiry_propagates_withdrawal_to_observer`.

---

## 2026-07-02 (IPv6 export policy)

### [pathvectord] Close the IPv6 export-policy gap — `propagate_prefix_v6` now evaluates export policy

Found during a follow-up bug/confidence pass on the RFC 9234 branch: `propagate_prefix_v6`
(`src/outbound.rs`) never consulted any export policy at all, unlike the IPv4 path
(`propagate_prefix`), which does. This meant every export policy an operator configured —
including RFC 9234's OTC egress block/attach terms, installed correctly into a policy that
was simply never evaluated — had zero effect on IPv6 UPDATEs. A dual-stack deployment would
correctly block a v4 route leak to a Provider while leaking the identical route over v6.
IPv6 route *attributes* already present (including OTC) were still correctly preserved and
re-emitted on egress; only policy *enforcement* was skipped.

Fixed by adding a new `export_policies_v6: HashMap<Ipv4Addr, Policy<Route<Ipv6Addr>>>` map
to `DaemonState` (built in `DaemonState::new()`, `add_peer`, and `remove_peer`, mirroring
`import_policies_v6`'s lifecycle — there is still no separate `export_default_v6` config
knob, so the single `export_default` value governs both families), giving
`propagate_prefix_v6` an `export_policy` parameter that it now evaluates exactly like
`propagate_prefix` does. Wired into all four call sites that build IPv6 UPDATEs:
`propagate_to_all_peers_v6` (incremental propagation), `on_established`'s IPv6 full-table
dump, and GR's `repropagate_after_stale_mark_v6`/`prune_stale_nlri_v6`. `set_export_default`
(gRPC `PolicyService`) now updates and re-evaluates both families instead of only IPv4.
Extended the existing `assert_consistent` proptest invariant (`daemon/mod.rs`) to also
check `export_policies_v6` key-set consistency across arbitrary add/remove sequences, to
catch a future maintainer forgetting to keep the two maps in sync.

---

## 2026-07-02 (RFC 9234 bug audit)

### [pathvector-policy, pathvectord] Fix two real bugs found during a dedicated bug/confidence audit

Prompted by "do you have high confidence this is correct, and what about performance" —
a deliberate audit pass looking specifically for bugs, not just missing test coverage.

**Bug 1 — policy replacement silently disabled leak protection.** The gRPC-triggered
`PolicyService::set_import_default`/`set_export_default` handlers did
`self.import_policies.insert(peer_ip, Policy::new(action))` — a full replacement of the
peer's `Policy`, discarding any installed terms. Proved with a throwaway reproduction
before fixing: an RFC 9234 OTC leak-detection term count dropped from 1 to 0 after a
single `set_import_default` call, no warning, no error. This also silently disabled the
pre-existing RFC 6811 ROV reject term via the same code path — not unique to RFC 9234.
Fixed by adding `Policy::set_default` (changes only the default action, in
`pathvector-policy/src/term.rs`) and using it in both handlers instead of `Policy::new`.

**Bug 2 — no eBGP guard on Role/OTC.** RFC 9234 is eBGP-only by definition, and the
original implementation plan's own Non-goals section called for guarding Role/OTC
application on `PeerType::External` — but the guard was never actually implemented.
Confirmed via direct code inspection: no `is_ebgp` check existed anywhere near the
`role` handling. An operator who set `role` on an iBGP peer (even by mistake) would get
`Capability::Role` sent in OPEN to an internal router and OTC leak-detection applied to
iBGP-learned routes, which could incorrectly reject a route that legitimately carries
OTC from its original eBGP ingestion elsewhere in the network. Fixed with a new
`effective_role()` helper (`pathvectord/src/daemon/mod.rs`) that returns `None` — with a
one-time `tracing::warn!` — when `role` is configured on a peer where
`remote_as == local_as`; wired into every call site that previously read `peer.role`
directly (`DaemonState::new`, `add_peer`, `build_daemon`'s static-peer spawn loop, and
the dynamic `AddPeer` command handler).

**Performance:** re-benchmarked `pathvector-rib`'s full suite (`select_best`,
`loc_rib_insert`, `outbound_pipeline`) against a clean `main` checkout in an isolated
`git worktree` — all within ~1-2% of `main` (noise), no regression. Matches the
architectural expectation that OTC storage (lazily allocated on `RareAttrs`) adds only
O(1) checks on the hot path.

---

## 2026-07-02 (RFC 9234 correctness reflection)

### [pathvectord] Close test-coverage gaps found during a post-implementation review

Prompted by a deliberate "did we actually prove this correct" pass on the RFC 9234
work above, rather than new feature scope. Independently re-checked the OTC
ingress/egress role mapping against the RFC 9234 datatracker text directly (not
from memory of the feature's own earlier development) — confirmed correct,
including the Peer role's simultaneous ingress-attach/egress-attach/egress-block
handling. Ran the grown `pathvector-fuzz` targets (`session_framing`,
`session_message`) for 60s each, ~10M executions apiece, no crashes — called for
in the original plan but never actually executed until now.

Closed five real daemon-level test-coverage gaps: RouteServer and RsClient roles
had zero route-behavior tests (only a term-count assertion); Peer role's egress
interaction (simultaneous block-if-leaked and attach-if-absent) was untested;
Peer role's "OTC present and correct" accept path was untested; IPv6 ingress OTC
extraction was only proven to compile, never exercised by a real v6 UPDATE;
`build_local_capabilities`/`SpawnConfig::capabilities` had no test touching the
`role` parameter at all.

Also closed a real, larger gap: no test exercised the actual event-loop
reconnect capability-refresh path (`SessionEvent::Terminated` →
`SessionCommand::SetCapabilities`) — nothing in the suite referenced
`SetCapabilities` at all, meaning neither RFC 9234 Role nor the pre-existing
RFC 4724 R-bit reconnect fix had integration-level coverage, only unit tests on
the pure functions underneath. New test drives `run_event_loop` through
Established → Terminated (unclean) via the existing `MockSessionHandle`
infrastructure and asserts on the actual `Vec<Capability>` resent — proving both
survive a real reconnect, not just that the function that computes them is
correct in isolation.

---

## 2026-07-02 (RFC 9234)

### [pathvector-types, pathvector-session, pathvector-rib, pathvector-policy, pathvectord] RFC 9234 — BGP Role + `ONLY_TO_CUSTOMER` route-leak prevention

Closes `TODO.md`'s last remaining Tier-1 ("blocks operating safely on the internet")
item. Route leaks — a customer re-advertising a provider's route to another
provider — are responsible for a large class of real-world BGP incidents (the 2019
Verizon/Allegheny/Cloudflare leak being the canonical example). RFC 9234 closes this
mechanically: each eBGP session gets an explicit configured role (Provider / Customer
/ Peer / Route-Server / RS-Client), and an `ONLY_TO_CUSTOMER` (OTC) path attribute
prevents a leaked route from ever being re-advertised somewhere it shouldn't go — no
manual filter-list maintenance required.

Added a shared `Role` enum to `pathvector-types`. `pathvector-session` gained the BGP
Role capability (code 9), role-pair correctness validation during OPEN exchange
(NOTIFICATION subcode 11 on an incompatible pair; RFC 9234's own non-strict default —
absence of Role on either side is not a mismatch), and the OTC path attribute (type
35, optional+transitive). `pathvector-rib` gained lazily-allocated OTC storage on
`Route<A>`. `pathvector-policy` gained `OtcLeakCondition` (ingress leak detection),
`OtcPropagationCondition` (egress block), and `SetOtc` (attach-if-absent, shared
between the ingress and egress call sites) — all keyed off `session_role`, the role
*we* play on a given session (RFC 9234's own rule text is phrased in terms of the
peer's role, which is easy to misapply directly; every doc comment translates it
explicitly, since getting this backwards silently inverts the whole mechanism — a bug
caught and fixed during this feature's own development, before it reached daemon
wiring).

`pathvectord` gained `PeerConfig.role`, threaded the configured Role into each
session's OPEN capabilities (rebuilt per-session-spawn, including on reconnect — the
same lesson learned from the GR R-bit lifetime bug), and installs the OTC policy terms
into every peer's import/export policy for both static and dynamically-added peers.
Configured and negotiated Role are exposed via `PeerState.configured_role`/
`negotiated_role` over gRPC and in `pathvector peer get`'s detail output.

**Real e2e proof, not just unit tests:** a new `pathvector-e2e/tests/role.rs` proves
the full pipeline over an actual BGP session using a small custom mock BGP peer
(`pathvector-e2e/src/bin/mock_bgp_peer.rs`) rather than a real router — FRR 8.4.4 (the
version pinned in `Dockerfile.frr`) does fully support RFC 9234, but a well-behaved,
RFC-9234-conformant router will never produce a genuine leak by construction: role-pair
validation at OPEN time makes it structurally impossible for two correctly configured
routers to leak between each other. Reproducing a real leak over the wire requires a
peer willing to send one on purpose.

**Two non-blocking follow-ups tracked in `TODO.md`:** strict mode (the RFC makes it
optional and non-default), and OTC egress *enforcement* for IPv6 routes — discovered
along the way that `propagate_prefix_v6` never consults `export_policies` at all, a
pre-existing gap unrelated to this feature. IPv6 OTC attributes are still correctly
preserved and re-emitted on egress; only the block/attach policy terms can't run for
IPv6 until that gap closes.

---

## 2026-07-02 (Phase 2)

### [pathvector-policy, pathvector-rpki, pathvectord] RPKI Phase 2 — automatic route filtering on ROA validity

Phase 1 (see below) shipped a read-only RTR client and ROA cache; this closes the
`TODO.md`-tracked follow-up by making pathvectord actually reject invalid routes,
matching RFC 7115 / BIRD / FRR default convention.

Added `RoaValidityCondition<A>` to `pathvector-policy` — an RFC 6811 `Condition<R>` that
captures an `RtrHandle` at construction and matches routes whose ROA validity equals a
target state. Address-family dispatch (`validate_v4` vs `validate_v6`) is bridged
through a small sealed `RoaLookup` trait so the condition stays one generic `impl`
(mirroring `PrefixListCondition`'s existing style) rather than two impls that would risk
coherence-checker overlap.

`pathvectord` wires a "reject `Invalid`" term into every configured peer's IPv4 and IPv6
import policy via a new `DaemonState::install_rpki_import_terms`, called once right
after the RTR client spawns (not threaded through `DaemonState::new`, to avoid touching
its ~30 existing test call sites). Gated by a new `[daemon.rpki].reject_invalid` config
field, default `true`; set to `false` for RPKI monitoring-only mode. `Valid` and
`NotFound` routes are unaffected — they fall through to each peer's existing default
action exactly as before this change.

Also added a `test-util` Cargo feature to `pathvector-rpki` exposing
`RtrHandle::for_testing(v4, v6)` — builds a handle with deterministic pre-seeded ROA
data, so both `pathvector-policy` and `pathvectord` get fast, network-free ROV tests
instead of needing a mock RTR server.

## 2026-07-02

### [pathvectord, pathvector-rpki] Real-world RPKI smoke test against Routinator — found and fixed a wrong default port

Every RPKI test up to this point ran against a hand-rolled mock RTR server. Ran
`pathvectord` against a real `nlnetlabs/routinator` Docker container with a fully-synced
live RPKI table (~970k VRPs, all five RIRs) to validate the whole stack end-to-end —
config → RTR client → ROA cache → gRPC → CLI — against real protocol behavior and real
data, not synthetic fixtures.

**Result:** connected, negotiated RTR v1 with the real server, synced 969,408 ROA
entries. Validated three real (prefix, origin AS) outcomes against live data and got all
three right: `1.0.0.0/24` origin `AS13335` (Cloudflare) → `VALID`; the same prefix with a
wrong origin AS → `INVALID`; `192.0.2.0/24` (RFC 5737 TEST-NET-1, deliberately
unallocated) → `NOTFOUND`. Also confirmed the IPv6 "exceeds ROA max-length" case
(`2001:200::/48` under a ROA whose max-length is `/32`) correctly returns `INVALID`, not
`NOTFOUND`. Zero warnings or errors logged during the session.

**Bug found:** `RpkiConfig::port`'s documented default of `8323` was wrong — that's
Routinator's *HTTP* status/metrics port, not its RTR port. The default `--rtr` port is
`3323`. Confirmed directly against the published Docker image's exposed ports and default
`CMD`. Fixed the default in both `pathvectord::config::default_rtr_port` and
`pathvector_rpki::RtrConfig::default()`, plus doc comments in both crates.

**Also added:** an "RPKI Route Origin Validation" section to `pathvectord/README.md`
(previously undocumented — the feature had shipped without a README section), using the
real numbers from this smoke test as the worked example rather than placeholder values.

## 2026-07-01

### [pathvector-rpki] RTR client hardening — three gaps found and closed via RFC re-review

After Phase 1 shipped, a deliberate re-verification pass against the actual RFC 8210 §5
text (not memory) confirmed every fixed-size PDU wire format byte-for-byte, and found
three real gaps in `client.rs`:

1. **Version fallback was too narrow.** The client only downgraded from v1 to v0 on an
   explicit `ErrorReport { error_code: 4, .. }`. RFC 8210 §5 documents a broader real-world
   case: a v0-only cache "responds with a version 0 response" directly, no error at all.
   `read_pdu` previously discarded the wire version byte it decoded, so `sync_once` had no
   way to notice a silent mismatch — every subsequent outbound query would keep encoding at
   v1 even after a v0 cache had already accepted the session. Fixed by threading the
   observed version out of `read_pdu` and adopting it on any `CacheResponse`, not just an
   explicit rejection.
2. **Unbounded allocation from an untrusted length field.** `read_pdu` allocated
   `vec![0u8; remaining]` directly from the PDU header's `u32` length field — a
   misbehaving or compromised RTR server could declare a length near `u32::MAX` and force
   a multi-gigabyte allocation attempt per PDU. Added `MAX_PDU_LEN` (64 KiB, generous for
   any legitimate PDU) checked before any allocation.
3. **Two protocol paths were implemented but only exercised indirectly.** `CacheReset`
   received mid-diff-stream (server can't serve an incremental update, client must restart
   with a fresh Reset Query on the same connection) and an unsolicited `SerialNotify`
   during the idle phase (must trigger immediate resync, not wait for the refresh timer)
   both had working code but no test that isolated them.

Three new tests close gap 3 directly (`cache_reset_mid_stream_triggers_full_resync_on_same_connection`,
`unsolicited_serial_notify_triggers_immediate_resync_not_timer_wait`), two more prove gap 1
is fixed (`server_silently_replies_at_v0_without_error_report`,
`adopted_version_is_used_for_subsequent_queries`), and one proves gap 2
(`oversized_pdu_length_is_rejected_without_allocating`). Every one of these six tests was
verified twice: once passing against the fix, once failing when the corresponding fix was
temporarily reverted — confirming each test actually exercises the behavior it claims to,
not a false-positive pass. 65 tests total (up from 60), zero clippy warnings.

### [pathvector-rpki, pathvectord, pathvector-client, pathvector] RPKI Route Origin Validation — Phase 1 (RTR client, read-only)

New `pathvector-rpki` crate implementing the RTR (RPKI-to-Router) protocol client
per RFC 8210 (v1, primary) with RFC 6810 (v0) automatic fallback, and an RFC 6811 §2
ROA validity cache. Connects to an external validator (Routinator, rpki-client,
OctoRPKI, Cloudflare gortr) — no RPKI repository sync or certificate crypto
validation is done in-process.

Deliberately scoped narrow for this phase: no `pathvector-policy` condition, no
`Route<A>` changes, no automatic route filtering. Proves out the hardest new
protocol code (RTR session handling, ROA table correctness) before wiring it into
route-acceptance decisions — see TODO.md for the tracked Phase 2 follow-up.

**`pathvector-rpki` internals:**
- `pdu.rs` — RTR PDU codec (all RFC 8210 §5 PDU types), `Cursor`/`Writer`
  bounds-checked framing mirroring `pathvector-session`'s BGP codec.
- `table.rs` — ROA cache built on `routemap::RouteMap` (an existing sibling-project
  crate). Composes `RouteMap`'s single-winner LPM primitives into RFC 6811's "any
  covering ROA" semantics via a fast `NotFound` short-circuit + ancestor-prefix walk.
  A differential proptest against a naive linear-scan reference model caught a real
  bug in the first draft (the short-circuit conflated "contains this address at any
  length" with "covers this prefix at length ≤ query length") — fixed and preserved
  as a regression case in `proptest-regressions/table.txt`.
- `client.rs` — session state machine (connect → version-negotiate → sync →
  idle-until-refresh-or-notify → reconnect-with-backoff), tested against a
  hand-rolled mock RTR server: full sync, v1→v0 fallback, disconnect mid-session
  (stale data survives — a blackhole operator's ROV decisions are better served by
  stale-but-recent data than no data), and session-ID-mismatch detection.
- `error.rs` — manual `Display`/`Error` impls (no `thiserror` — matches the
  workspace convention already set by `pathvector-session`).

**`pathvectord` wiring:** new `[daemon.rpki]` config table (`host`, `port`; defaults
to Routinator's conventional 8323) and `DaemonState.rpki: Option<RtrHandle>`. Spawned
in `run_with` right after the metrics-install block, following the same
graceful-degradation philosophy as the FIB writer and Prometheus exporter:
`RtrClient::spawn` is async-forever and never blocks startup — connection failures
surface later via `RtrStatus.connected == false`, which is why the gRPC/CLI status
surface matters.

**gRPC surface:** new read-only `RpkiService` (`GetRpkiStatus`, `ValidateRoa`) added
to `proto/pathvector/v1/management.proto` (and its manually-synced copy in
`pathvector-client/proto/` — no symlink exists between the two, confirmed before
editing). `ValidateRoa` reuses the existing `Nlri<Ipv4Addr>`/`Nlri<Ipv6Addr>` CIDR
parsing rather than introducing a new helper.

**`pathvector-client` + CLI:** new `types::RoaValidity` / `types::RpkiStatus` domain
types, `DaemonClient::get_rpki_status()` / `validate_roa()` trait methods (implemented
for the real gRPC client and every test double), and new `pathvector rpki status` /
`pathvector rpki validate <prefix> <asn>` CLI subcommands.

**Test coverage:** 60 tests in `pathvector-rpki` (PDU codec round-trips + proptests,
ROA table unit + differential proptest, mock-server client integration tests), 9 new
`pathvectord` tests (2 daemon wiring, 7 gRPC handler), 9 new `pathvector-client` tests
(conversion edge cases), 9 new `pathvector` CLI tests (dispatch + output smoke tests).
Zero clippy warnings workspace-wide.

### [pathvectord] Prometheus metrics endpoint

**`/metrics` HTTP endpoint** — new `metrics_port: Option<u16>` field in `[daemon]` config.
When set, pathvectord serves Prometheus text-format metrics on `0.0.0.0:<metrics_port>`.
Omitted by default (no behavior change for existing deployments). New `pathvectord/src/metrics.rs`
module owns all instrumentation.

**Metrics exposed:**
- Gauges: `pathvectord_bgp_session_up{peer}`, `pathvectord_bgp_session_established_timestamp_seconds{peer}`,
  `pathvectord_bgp_adj_rib_in_prefixes{peer}`, `pathvectord_bgp_adj_rib_out_prefixes{peer}`,
  `pathvectord_bgp_loc_rib_prefixes{afi}`
- Counters: `pathvectord_bgp_sessions_established_total{peer}`,
  `pathvectord_bgp_sessions_terminated_total{peer,reason}`, `pathvectord_bgp_updates_received_total{peer}`

Hooked into the real event loop at three sites in `daemon/mod.rs`: session established/terminated,
route update processing, and post-`flush_pending()` RIB size updates.

**Graceful degradation on bind failure** — `metrics::install()` returns `Result` rather than
panicking. A metrics port conflict (e.g. already in use) logs a warning and the daemon continues
running BGP sessions normally — matches the existing FIB-writer failure pattern in `main.rs`
rather than being a hard dependency.

**Test coverage:**
- 5 unit tests in `pathvectord/src/metrics.rs` using `metrics-util`'s `DebuggingRecorder` +
  `metrics::with_local_recorder` to assert on emitted values/labels in isolation.
- 4 e2e tests in `pathvector-e2e/tests/metrics.rs` (new `MetricsHarness`) that stand up a real
  pathvectord + GoBGP session and scrape the actual HTTP endpoint — proving the event-loop hooks
  are correctly wired, not just correct in isolation.

  Running these against real containers caught two real issues in the first drafts, both in the
  test's assumptions rather than the daemon: (1) the `metrics` crate does not materialize a gauge
  series until its first `.set()` call, so an initial "must equal 0 before any route arrives"
  assertion was wrong; (2) a follow-up "series must not exist at all before any route arrives"
  assertion — meant to fix (1) — was itself a race: GoBGP's e2e config
  (`write_gobgp_config`) always enables RFC 4724 graceful-restart, so it sends an End-of-RIB
  marker (an empty UPDATE) immediately after `Established`, independent of whether pathvectord
  negotiates GR. That EOR flows through `on_route_update` in the real event loop and
  unconditionally materializes `adj_rib_in_prefixes{peer}` at `0` — before the test's real route
  announcement. This raced against the test's baseline check and flaked under GitHub Actions'
  scheduling while passing locally. Fixed by dropping the pre-announce assertion entirely and
  keeping only the deterministic invariant: the gauge reaches `1` after the real announce.

**Known limitation (tracked in TODO.md):** metric series are labeled by peer IP and are zeroed
but never removed on `RemovePeer`. Non-issue for static peer sets; unbounded growth for
deployments with frequent dynamic peer churn via the gRPC API.

**Documentation** — full metrics reference, sample scrape output, Prometheus scrape config,
and PromQL query examples added to `pathvectord/README.md` Observability section.

---

## 2026-06-24

### [pathvector-session, pathvectord] RFC 8538 — NOTIFICATION support for BGP Graceful Restart

Full implementation of RFC 8538 (extends RFC 4724 GR with NOTIFICATION-triggered restarts).
N-bit set in the GracefulRestart capability when GR is enabled locally; peer's N-bit tracked
on `Established`. A non-HardReset CEASE received from a peer with both sides' N-bit set opens
the GR window (routes held, stale-marked, subject to the deadline timer) instead of flushing
immediately. `CEASE/HardReset` (subcode 9) always flushes immediately regardless of N-bit
state, per §5.

11 unit tests cover the N-bit negotiation and eligibility logic. 2 e2e tests: one against
GoBGP (validates the §5 Hard Reset bypass path — GoBGP 4.6.0 sends `CEASE/HardReset` on all
shutdowns) and one against FRR (validates the §4 positive path — FRR sends non-HardReset
`CEASE/AdministrativeShutdown` on `docker stop`, confirming the GR window opens and expires
correctly). See `pathvectord/RFC.md` for the full clause-by-clause status.

---

## 2026-06-22

### [pathvector-session, pathvector-rib, pathvectord] RFC 4724 Graceful Restart — Phase 1 (Helper) + Phase 2 (Speaker)

**Phase 1 — Helper role:** pathvectord advertises `restart_time` and marks IPv4/IPv6 unicast
families `forwarding_preserved` in its GracefulRestart capability when `graceful_restart_time`
is configured, so upstream peers hold pathvectord's routes across a restart.

**Phase 2 — Speaker role:** pathvectord holds a peer's routes as stale (not withdrawn) when
that peer's session terminates uncleanly and the peer had advertised GracefulRestart with
`restart_time > 0`. A deadline timer (wired into the main event loop's `tokio::select!`) flushes
stale routes if the peer does not re-establish within the window; routes not re-announced by
the time the peer sends its End-of-RIB marker on re-establishment are pruned.

**`daemon.rs` restructured into 8 submodules** (`daemon/mod.rs`, `capabilities.rs`, `fib.rs`,
`gr.rs`, `origination.rs`, `peer.rs`, `policy.rs`, `route.rs`). The four previously-scattered GR
fields on `DaemonState` consolidated into a `GracefulRestartState` struct with
`earliest_deadline()`, `drain_expired()`, and `remove_peer()` helpers. An O(n²) `Vec::contains`
in `repropagate_after_stale_mark_v4` fixed to a `HashSet` lookup. A double write-lock bug in the
GR deadline branch corrected.

**e2e coverage:** `gr_phase2_eor_prunes_stale_routes_not_refreshed_by_peer` uses
`docker network disconnect/connect --ip` to simulate a partial-RIB restart without changing the
GoBGP container IP; `connect_retry_time` made configurable (default 120s, 2s in the test harness)
to keep the test fast.

**Unit coverage:** `gr_re_termination_during_window_resets_deadline_and_holds_routes` confirms
the deadline is refreshed and routes are not double-flushed on a second unclean disconnect;
`gr_clean_termination_during_window_flushes_immediately` confirms a NOTIFICATION received inside
a GR window overrides the window and flushes immediately.

See `pathvectord/RFC.md` for clause-by-clause RFC 4724 status.

---

## 2026-06-21

### [pathvectord] End-of-RIB marker — full RFC 4724 §2/§3 implementation (send + receive)

**Send side** — after each full-table dump on session establishment, `on_established` now sends:
- An **IPv4 EOR** — a minimum-length UPDATE (empty withdrawn, empty attributes, empty announced) — to all peers
- An **IPv6 EOR** — an UPDATE carrying an empty `MP_UNREACH_NLRI` for IPv6 unicast — to peers that negotiated the IPv6 Multiprotocol capability

EOR is skipped (and the session is stalled) if the channel is full during the dump.

**Receive side** — `on_route_update` detects EOR markers from peers before any route processing:
- IPv4 EOR: all-empty UPDATE (no withdrawn, no attributes, no announced NLRIs)
- IPv6 EOR: UPDATE with a single empty `MP_UNREACH_NLRI { afi_safi: IPV6_UNICAST }`

Detected EOR markers are recorded per-peer in `RibSnapshot` (`eor_received` / `eor_received_v6` `HashSet`s) and exposed via two new `PeerState` fields in the management API: `eor_ipv4_received` and `eor_ipv6_received`. State is cleared on session termination and re-establishment.

**GracefulRestart capability (RFC 4724 §3)** — pathvectord now advertises `Capability::GracefulRestart { restart_flags: 0, restart_time: 0, families: [] }` in OPEN messages. Without this, peers such as GoBGP 4.6.0 withhold EOR markers (they only send EOR when graceful restart is bilaterally negotiated). `build_local_capabilities(local_as)` was extracted to consolidate the two previously divergent capability lists (static-config peers and gRPC `AddPeer` peers) into a single source of truth; this also fixed a pre-existing bug where the dynamic-peer path was missing `RouteRefresh`.

**Wire encoding** — confirmed: IPv4 EOR encodes to exactly 23 bytes (RFC 4271 §4.3 minimum UPDATE length); IPv6 EOR survives codec roundtrip. Four wire-level tests added to `pathvector-session`.

**Test coverage:**
- 9 unit tests in `pathvectord`: `test_ipv4_eor_received_is_recorded`, `test_ipv6_eor_received_is_recorded`, `test_ipv4_eor_does_not_insert_route`, `test_eor_state_cleared_on_termination`, `test_update_with_attributes_is_not_eor`, `test_eor_state_cleared_on_re_establish`, plus 3 stall-path tests
- 4 e2e tests against GoBGP 4.6.0: `eor_on_empty_rib_does_not_cause_session_reset`, `eor_after_full_table_dump_does_not_cause_session_reset`, `eor_ipv4_received_from_gobgp_is_recorded`, `eor_ipv4_received_persists_after_route_churn`

**Deferred:** Stale-route timer (RFC 4724 §4.2) and FSM-level graceful restart restart-state signaling.

---

## 2026-06-20

### [pathvectord] Cross-UPDATE NLRI coalescing in outbound pipeline

Implements RFC 4271 §9.2: "the speaker SHOULD try to combine as many feasible routes as
possible in the UPDATE messages."

**Mechanism** — `DaemonState` now accumulates outbound `PrefixDecision`s in per-peer
`pending_decisions` / `pending_decisions_v6` buffers instead of calling `flush_updates`
immediately on each `on_route_update`. The event loop drains all immediately-available
events via `try_recv` after each initial `recv`, then calls `flush_pending` once when the
channel goes quiet. `flush_updates` sees the combined set of decisions across all buffered
route updates and packs NLRIs sharing the same attribute set into single UPDATE messages.

**Correctness fixes applied during review:**
- gRPC-facing mutation methods (`originate_routes`, `withdraw_originated_routes`,
  `set_import_default`) self-flush via `flush_pending()` at the end of each method, so
  routes originated or policies changed via gRPC are sent immediately without waiting for
  the next BGP event.
- The MRAI timer arm now calls `flush_pending()` after `flush_mrai_pending()` because
  `flush_mrai_pending` calls `propagate_to_all_peers` which buffers; without the second
  flush, MRAI-released routes would be delayed until the next event loop iteration.
- `on_fib_change` propagation is flushed in the `fib_changed` event loop arm.
- Mandatory attribute errors detected in the batch-drain loop (RFC 4271 §6.3) are now
  handled correctly: `flush_pending` is called for other peers, then `SessionCommand::Notification`
  is sent to the erroring peer before resuming the outer event loop.
- Peer termination (`on_terminated` and `remove_peer`) clears both `pending_decisions` and
  `pending_decisions_v6` so terminated sessions never receive stale decisions.

**Tests added:**
- `flush_pending_coalesces_multi_update_burst` — two `on_route_update` calls with identical
  attributes produce a single outbound UPDATE message for the receiving peer (not two).
- `flush_pending_clears_on_terminated` — buffered decisions for a terminated peer are
  discarded and not sent.

All 443 existing tests updated to call `flush_pending()` where they previously relied on
immediate channel writes.

### [pathvector-mrt] Convergence detection via snapshot polling instead of watch_routes quiescence

`pathvector-mrt` now polls snapshots every 50ms and declares convergence based on
time-since-last-change rather than two identical consecutive counts. The `watch_routes`
delta-stream approach was attempted first but the broadcast channel drops slow consumers at
1M+ event/s flood rates during MRT replay. The 50ms-interval snapshot approach gives adequate
accuracy (~200ms window) without the reconnect-on-lag problem.

---

## 2026-06-19 (continued, 3)

### [pathvectord, pathvector-e2e] `next_hop_self` e2e test + `peer_bgp_ids` race window fix

**`next_hop_self` e2e test** — `rr_next_hop_self_rewrites_reflected_next_hop` added to
`pathvector-e2e/tests/route_reflector.rs`. Spins up the three-container RR topology with
`next_hop_self = true` on both peers, announces a route from the client with an
unreachable next-hop (`192.0.2.1`), then verifies via `gobgp global rib` that the
non-client received pathvectord's bridge address as NEXT_HOP — confirming the rewrite
happened at the wire level. `get_gobgp_next_hop` added to `pathvector-e2e/src/lib.rs`.
`RrHarness::new_with_next_hop_self` added for the NHS topology.
`RrHarness.pathvectord_addr` exposed so tests can assert the exact expected NEXT_HOP.

**`peer_bgp_ids` race window closed** — `on_established` now accepts
`peer_bgp_id: Ipv4Addr` as an explicit parameter and inserts it into
`rib.peer_bgp_ids` atomically with `rib.peer_types`. The caller (`run_event_loop`)
no longer inserts it separately. This eliminates a latent window where the ORIGINATOR_ID
injection code (which falls back to `peer_ip`) could have observed an absent entry.

---

## 2026-06-19 (continued, 2)

### [pathvectord, pathvector-rib] `next_hop_self` + `best_peer()` double-call fix

**`next_hop_self`** — forces NEXT_HOP to the local router address on iBGP
re-advertisements. Required when the route reflector is an eBGP border router and
clients can't reach the original eBGP next-hop directly.

- `PeerConfig::next_hop_self: bool` field added (`pathvectord/src/config.rs`)
- `RibSnapshot::next_hop_self_peers: HashSet<Ipv4Addr>` populated at startup and
  maintained through `add_peer` / `remove_peer`
- `prepare_outbound` and `prepare_outbound_v6` now accept `next_hop_self: bool`; for
  iBGP peers with the flag set, NEXT_HOP is rewritten to `local_next_hop`/`local_ipv6`
  (has no effect on eBGP peers — their NEXT_HOP is always rewritten)
- All propagation paths (`propagate_to_all_peers`, `propagate_to_all_peers_v6`,
  `on_established`, `on_terminated`, `set_export_default`) look up `next_hop_self` per
  peer and pass it through
- Unit test: `test_propagate_to_all_peers_next_hop_self_rewrites_ibgp_next_hop`
  (builds a full `DaemonState`, inserts an eBGP-learned route, and verifies the iBGP
  UPDATE carries the session local address rather than the original next-hop)
- 4 lower-level tests in `pathvector-rib/src/outbound.rs` covering all four cases
  (IPv4/IPv6 × `next_hop_self` true/false)

**`best_peer()` double-call eliminated** — `propagate_prefix` and `propagate_prefix_v6`
previously called `loc_rib.best_peer(&nlri)` internally for split-horizon checking, and
the daemon's RR split-horizon closure called it again for the same nlri. Both are O(1)
HashMap lookups so no measurable overhead, but the two calls could theoretically observe
inconsistent state in a concurrent design. The internal call is now computed once at the
top of each function and reused, eliminating the duplication.

---

## 2026-06-19 (continued)

### [pathvectord, pathvector-e2e] Route reflector gap fixes and e2e validation

**`reapply_import_policy_v6`** — `set_import_default` previously only re-evaluated
the IPv4 Adj-RIB-In on policy reload. IPv6 routes were silently left under the old
policy until the session was torn down. `reapply_import_policy_v6` added (parallel to
the IPv4 function); `set_import_default` now calls both. Two new unit tests:
`test_reapply_v6_accepts_previously_rejected_route`,
`test_reapply_v6_rejects_previously_accepted_route`.

**`RrHarness` — e2e route reflection tests** — `pathvector-e2e` gains a three-container
RR topology: GoBGP-client (`is_rr_client = true`, AS 65002 iBGP), pathvectord (RR,
AS 65002), GoBGP-non-client (plain iBGP, AS 65002). Three tests in
`pathvector-e2e/tests/route_reflector.rs`, all confirmed passing against Docker:
- `rr_client_route_reflected_to_non_client` — client route crosses iBGP split-horizon
  via reflection (the core RFC 4456 §8 invariant)
- `rr_non_client_route_reflected_to_client` — non-client → client path
- `rr_client_route_visible_in_pathvectord_rib` — reflected route appears in
  pathvectord's own Loc-RIB via gRPC

**`cluster_id` documentation** — `DaemonConfig::cluster_id` doc comment expanded with
an explicit multi-cluster warning: distinct `cluster_id` values required per cluster;
sharing a `cluster_id` across independent clusters causes CLUSTER_LIST loop detection
to fire incorrectly.

---

## 2026-06-19

### [pathvectord, pathvector-rib] RFC 4456 §8 — BGP Route Reflection (full compliance)

Full implementation of RFC 4456 §8 route reflector semantics, covering inbound
attribute injection, loop detection, split-horizon enforcement, and IPv4/IPv6 parity.

**Inbound attribute injection** — `on_route_update` now processes RFC 4456 attributes
for all iBGP peers (clients and non-clients) when acting as an RR. Previously the
guard was `rr_clients.contains(&peer_ip)` (clients only). The correct scope is
`is_rr && peer_type == PeerType::Internal` — any iBGP peer can reflect routes.

**ORIGINATOR_ID loop detection** — discards UPDATE if `ORIGINATOR_ID` equals the
local BGP ID. Detects routes that have looped back through the cluster.

**CLUSTER_LIST loop detection — extended scope** — previously only fired for routes
from configured clients. Now fires for all iBGP peers, including non-client peers
that carry a `CLUSTER_LIST` set by another RR.

**Architecture fix** — all RFC 4456 processing (detection + injection) happens on
the original wire message in `on_route_update`, before `handle_update` stores the
route. This ordering is required: detecting loops on an already-enriched message
would produce false positives.

**IPv6 parity** — four IPv6 code paths were missing route-reflector semantics:
- `add_peer`: `adj_ribs_out_v6` always used `AdjRibOut::new`; fixed to use
  `new_reflecting` for iBGP peers when acting as an RR.
- `on_established` early reset: same bug; fixed.
- `on_established` full-table dump: no split-horizon check for v6; added.
- `propagate_to_all_peers_v6`: no split-horizon check; added, matching IPv4 path.

**Structural enforcement — `make_adj_ribs_out_pair`** — private helper that creates
both `adj_ribs_out` and `adj_ribs_out_v6` for a peer in a single call, ensuring
they can never have divergent `reflects()` state. All four construction sites use it.
`AdjRibOut::reflects()` accessor added for testability.

**Test coverage** — 13 new unit tests across the RR test block:
- 3 regression tests for ORIGINATOR_ID loop detection and non-client → client
  attribute injection (IPv4)
- 4 regression tests for IPv6 parity (reflecting mode, split-horizon in propagation
  and full-table dump)
- 4 invariant tests asserting `adj_ribs_out[p].reflects() == adj_ribs_out_v6[p].reflects()`
  after every mutation point (`new`, `add_peer`, `on_established`, `on_terminated`)
- Audit confirmed `reapply_import_policy` is not a bypass: RFC 4456 attributes are
  stored on the `Route` struct in `AdjRibIn` (set during `handle_update`) and survive
  the policy-reload cycle intact.

**RFC_REQUIREMENTS.md** — RFC 4456 updated from `⚠️` to `✅`; owner updated to
include `pathvectord` alongside `pathvector-rib`.

---

## 2026-06-18 (continued)

### [pathvector-session / pathvectord] Per-peer hold timer, RFC 9003 shutdown message, RFC 7313 codec, ROUTE-REFRESH trigger

Four small-to-medium protocol features added across `pathvector-session` and `pathvectord`.

**Per-peer hold timer** — `PeerConfig.hold_time: Option<u16>` added. `build_daemon` and the `AddPeer`
command processor fall back to `DaemonConfig.hold_time` when the per-peer value is absent, preserving
existing behaviour for all peers that do not override it.

**RFC 9003 — Extended admin shutdown communication** — `encode_shutdown_message` /
`decode_shutdown_message` added to `pathvector-session::message::notification`. Wire format: 1-byte
length prefix + UTF-8 string, max 128 bytes, in the CEASE NOTIFICATION `data` field. `pathvectord`
reads `shutdown_message: Option<String>` from `PeerConfig`; `RemovePeer` sends
`Cease/AdministrativeShutdown` with the encoded payload instead of a bare `Stop` command when a
reason is configured. 6 new unit tests (round-trip, truncation, empty-data, length-overrun,
NOTIFICATION integration).

**RFC 7313 — Enhanced Route Refresh codec** — `RouteRefreshSubtype` enum added to
`pathvector-session::message::route_refresh`. The previously reserved byte in the 4-byte ROUTE-REFRESH
wire format is now decoded as `Refresh` (0), `BeginRefresh` (1), `EndRefresh` (2), or `Unknown(u8)`.
`RouteRefreshMessage::new(afi_safi)` constructor added (subtype defaults to `Refresh`). Encode/decode
updated; all existing callers migrated; 4 new codec tests added.

**Outbound ROUTE-REFRESH trigger / `SoftReset` gRPC RPC** — `SessionCommand::RouteRefresh(RouteRefreshMessage)`
variant added to `pathvector-session::transport`. `SessionHandle::send_route_refresh` trait method
wired through `SpawnedSessionHandle` → command channel → session actor. `SoftReset` RPC added to
`PeerService` proto; `PeerServiceImpl::soft_reset` resolves the peer's session actor by IP, parses the
AFI/SAFI from the request, and sends a `RouteRefresh` command. `pathvector-client/tests/integration.rs`
updated with the new trait method on all mock implementations.

### [pathvectord] Dynamic peer loose-end fixes — broadcast safety, race-safety tests, restart persistence

Three correctness and operational gaps closed after the initial audit pass.

**`peer_tx` broadcast capacity comment:** Added an inline comment at the
`broadcast::channel(1024)` creation site explaining the bounded capacity,
`RecvError::Lagged` behavior, and the self-healing guarantee: the `watch_peers`
stream handler re-reads the full peer snapshot on any `Changed(peer: None)` signal,
so a lagging receiver catches up without permanent event loss.

**`incoming_senders` race-safety tests (2 new unit tests):**
- `remove_peer_clears_incoming_senders` — drives `RemovePeer` through the real
  `run_command_processor` and asserts the peer's entry is gone from `incoming_senders`
  before `Terminated` fires, proving the reconnect race window is closed at the
  command-handler level.
- `bgp_listener_drops_unlisted_peer` — starts the real TCP listener with an empty
  `incoming_senders` map, connects via loopback, and asserts EOF — the connection is
  RST'd immediately with no data sent.

**Restart persistence — `DynamicPeerStore` (6 unit tests + 2 integration tests):**
`config::DynamicPeerStore` writes a TOML sidecar (`dynamic_peers.toml`, same directory
as the static config) on every `add_peer` and `remove_peer` using atomic
write-then-rename. `main.rs` loads the sidecar at startup, merges its peers into
`cfg.peers` (skipping any address already in the static config), and passes the sidecar
path into `run_command_processor` for write-through. Six unit tests cover: load-absent
returns empty, upsert persists, upsert is idempotent by address, remove deletes,
remove-unknown is a no-op, full-field round-trip. Two `run_with_tests` integration
tests prove the restart path: sidecar peer gets a spawned session; static-config
duplicate is not spawned twice.

### [pathvector-rib] Criterion benchmark baseline — M2 Max

Three benchmark targets added to `pathvector-rib/benches/`, establishing the
performance baseline for the RIB and outbound pipeline on Apple M2 Max, 96 GB RAM.

**`select_best`** — RFC 4271 §9.1 best-path decision across N candidates:
- 2 candidates: **158 ns** (typical iBGP mesh)
- 10 candidates: **504 ns** (realistic eBGP fan-out)
- 100 candidates: **2.6 µs** (pathological; O(N) as expected)

**`loc_rib_insert`** — one insert into a pre-populated RIB triggering best-path
recompute:
- 10k prefixes: **614 ns** (full internet table range)
- 100k prefixes: **582 ns** (flat — HashMap lookup dominates, not table size)
- 500k prefixes: **2.1 µs** (mild L3 cache pressure; still sub-3 µs)

**`outbound_pipeline`** — `prepare_outbound` + `AdjRibOut::insert` per peer for
one prefix change, measured for minimal (2-hop path, no communities) and dense
(15-hop, 8 communities) routes:
- minimal/1 peer: **313 ns** | minimal/10: **1.4 µs** | minimal/50: **6.8 µs**
- dense/1 peer: **468 ns** | dense/10: **2.8 µs** | dense/50: **13.7 µs**

Per-peer amortised cost is constant (~136 ns/peer minimal, ~274 ns/peer dense);
community vec allocation accounts for the ~2× dense overhead.

---

## 2026-06-18

### [pathvectord, pathvector-client, pathvector] Dynamic peer robustness — correctness audit fixes

Six issues identified in a post-implementation audit of the `AddPeer`/`RemovePeer`
feature. All protocol-observable issues are resolved; two operational limitations
remain documented in `pathvectord/README.md`.

**`FAILED_PRECONDITION` guard for mid-teardown AddPeer (gap 1):** `grpc.rs` `add_peer`
handler now reads `pending_removal` before sending the `DaemonCommand`. Returns
`FAILED_PRECONDITION("peer removal in progress; retry after peer disappears from
list_peers")` rather than returning `OK` for an add that will be silently dropped.
The command processor also logs `warn!` and drops the add if the race is lost after
the pre-check passes.

**Correct `Removed` events on `WatchPeers` (gap 4):** Previously, `watch_peers`
subscribers received `Removed` events with zeroed `remote_as`/`local_as` because the
peer state was already erased before the stream handler could read it. Fixed by
capturing `remote_as` and `local_as` from the RIB *before* `on_terminated` and
`remove_peer` run, then broadcasting an explicit `proto::PeerEvent { type: Removed,
peer: Some(PeerState { address, remote_as, local_as, .. }) }` directly from the event
loop. `on_terminated` now accepts a `notify: bool` parameter — it suppresses its
intermediate `Changed(None)` broadcast during removal so the stream receives exactly
one `Removed` event, not a `Changed` followed by a `Removed`. The stream handler
forwards explicit `Removed` events directly rather than re-deriving them via snapshot
diffing. `dashboard.rs` `apply_peer_event` handles `Removed` with `retain`. Three new
unit tests cover `Removed`/partial-removal/unknown-address-no-op cases.

**Propagation stall observability (gap 5):** `on_terminated`'s re-propagation loop
now wraps its body with `Instant::now()` and emits `tracing::warn!` if the loop holds
the state write lock for more than 100 ms, including peer address, prefix count, and
elapsed milliseconds. Operators can now detect large-table removal stalls in production
before they cause cascading hold-timer failures.

**Command processor panic watchdog (gap 6):** `run()` now wraps the
`run_command_processor` join handle in a second `tokio::spawn` that logs
`tracing::error!` if the task exits with a panic, making the failure visible in
structured logs rather than silently breaking `AddPeer`/`RemovePeer`.

**`DynamicPeerHarness` + `wait_for_peer_absent` (gap 4 verification):** New e2e test
harness starts `pathvectord` with zero static peers. Four e2e tests: dynamic add
establishes session, idempotent add is a no-op, remove withdraws routes and removes
peer, add/remove cycle. `wait_for_peer_absent` polls `list_peers` until the target IP
disappears.

**Remaining open gaps:** dynamic peers don't survive daemon restart (gap 2); MD5
passwords on dynamically-added peers don't protect inbound connections because the
listener socket is bound once at startup (gap 3). Both are documented in
`pathvectord/README.md`.

---

## 2026-06-17

### [pathvectord, pathvector-client] Dynamic peer reconfiguration — AddPeer / RemovePeer gRPC RPCs

Runtime peer management without daemon restart. Operators can now add and remove BGP
peers over the gRPC management API while other sessions remain unaffected.

**Proto:** `AddPeer` and `RemovePeer` RPCs on `PeerService`; `AddPeerRequest` carries
address, remote AS, port, import/export default policy (`PolicyAction`), and optional
RFC 2385 MD5 password. AS 0 and AS 23456 (AS_TRANS, RFC 7607) rejected with
`INVALID_ARGUMENT`.

**Architecture:** `DaemonCommand` enum bridges the gRPC layer to the event loop without
leaking generics. A separate `run_command_processor` task handles commands so the event
loop signature stays stable. `incoming_senders` and `md5_passwords` are
`Arc<RwLock<HashMap>>` so the BGP listener picks up newly added peers immediately.
`stop_senders` is `Arc<Mutex<HashMap>>` with a lock-clone-await pattern so the sender
is never held across an `await`.

**Teardown sequencing:** `pending_removal: HashSet<Ipv4Addr>` in `DaemonState` signals
the `Terminated` handler to run a full state purge (`remove_peer` — clears all
per-peer RIB/policy maps) instead of a reconnect-ready reset (`on_terminated`). This
guarantees routes are withdrawn from the Loc-RIB before peer state is destroyed.

**Liveness fix:** if the session actor has already exited between reconnects (stop sender
dropped), the command processor synthesizes `SessionEvent::Terminated` directly via
`event_tx` so the `pending_removal` cleanup still runs.

**`AddPeer` is idempotent** — re-adding an existing peer is a no-op. `RemovePeer` on
an unknown peer returns `NOT_FOUND`.

**Client:** `AddPeerParams` type + `add_peer` / `remove_peer` on the `DaemonClient`
trait; `PathvectorClient` implementation; `MockDaemonClient` stubs.

Tests added: `add_peer_inserts_all_state_maps`, `add_peer_is_idempotent`,
`remove_peer_clears_all_state_maps`, `remove_peer_returns_false_when_not_found`,
`terminated_with_pending_removal_calls_remove_peer`,
`terminated_without_pending_removal_keeps_peer_state`,
`remove_peer_synthesizes_terminated_when_no_stop_sender`,
`test_add_peer_invalid_address`, `test_add_peer_rejects_as_zero`,
`test_add_peer_rejects_as_trans`, `test_add_peer_sends_command_on_valid_request`,
`test_remove_peer_invalid_address`, `test_remove_peer_not_found`,
`test_remove_peer_sends_command_when_peer_exists`.

### [pathvector-rib] RFC-correct same-AS MED comparison in best-path selection

RFC 4271 §9.1.2.2 requires MED to be compared only between routes from the same neighboring
AS. The prior implementation compared MED globally, and a partial pairwise fix was
non-transitive for 3+ routes across multiple ASes — `max_by` produces unspecified results on
a non-total order.

Correct algorithm (`select_best_with_oracle`):
1. Group candidates by `AsPath::neighboring_as()` (first ASN in first Sequence segment).
2. Select the best within each group — all routes share the same `neighboring_as()`, so
   `prefer()` applies MED correctly.
3. Compare group winners — different neighboring ASes, so `prefer()` skips MED, guaranteeing
   a total order.

`AsPath::neighboring_as()` added to `pathvector-types`. Tests: `test_med_ignored_for_different_neighboring_as`,
`test_med_compared_within_same_neighboring_as`. Proptest: `prop_med_winner_is_insertion_order_independent`
tries all six insertion orders of a 3-route cross-AS scenario and verifies the same peer
wins every time — this test would have directly caught the non-transitivity bug.

### [pathvector-rib, pathvectord] RIB memory optimisation — 57% reduction at 500k routes

Six-commit series reducing per-route memory from ~2.6 KB to ~0.57 KB at 500k routes:

1. **`LocRib` structural rewrite** — `best: RouteMap<A, PeerId>` stores the winning peer ID
   only (route always accessible via candidates lookup); flat `CandidateMap` +
   `PeerIndex<SmallVec<[PeerId; 4]>>` eliminates ~320 B per-prefix nested HashMap
   allocation. 500k routes: 1.4 GB → 605 MB.

2. **`AsPath` interning via `Arc<AsPath>`** — routes from the same BGP UPDATE share one
   `Arc<AsPath>` allocation. `RouteBuilder::with_shared_as_path` used in the UPDATE decode
   loop. CoW via `Arc::make_mut` in `prepare_outbound` when eBGP prepend is needed.
   Saves 16 bytes/route struct layout (Vec 24 B → Arc 8 B).

3. **Rare attribute boxing** — 7 attributes present in <5% of routes (`communities`,
   `large_communities`, `extended_communities`, `cluster_list`, `atomic_aggregate`,
   `aggregator`, `originator_id`) moved behind `Option<Box<RareAttrs>>`. Absent fields cost
   8 bytes (null pointer) instead of 96+ bytes of empty Vecs. 500k: 605 MB → 481 MB.

4. **AHash, SmallVec, `u32` timestamp** — `AHashMap`/`AHashSet` replaces `std::HashMap` in
   `LocRib` (eliminates SipHash overhead on internal keys). `PeerIndex` inner collection
   changed to `SmallVec<[PeerId; 4]>` (up to 4 peers inline, no heap). `Route::received_at`
   shrunk from `Instant` (16 B) to `u32` Unix seconds (4 B), saving 12 B/route.

5. **Empty `AsPath` static intern** — `RouteBuilder::new` returns a clone of a
   process-wide `Arc<AsPath>` for empty paths (originated routes). Eliminates 500k ×
   40 B heap allocations at scale. 500k: 486 MB → 461 MB.

6. **Extended phases** — stress harness extended from 3 phases (10k/100k/500k) to 6
   (10k/100k/250k/500k/750k/900k). At 900k routes: pathvectord 515 MB vs GoBGP 792 MB
   (35% less); convergence 0.26 s vs 0.56 s (2.2× faster). Per-route cost: 0.57 KB
   (pathvectord) vs 0.88 KB (GoBGP).

### [pathvector-stress] GoBGP 1:1 synthetic benchmark harness

New `pathvector-stress` workspace crate runs both daemons on the same host with identical
workloads and prints side-by-side convergence time and peak RSS. GoBGP bench phase spawns
`gobgpd`, calls `StartBgp`, injects routes via `AddPathStream` gRPC, then reads RSS via
`ps`. `just stress` (debug) / `just stress-release` (optimised, numbers worth recording).
Includes `pathvector-stress/README.md` with prerequisites, port assignments, and baseline
numbers.

### [pathvector-mrt] MRT TABLE_DUMP_V2 replay against live pathvectord

New `pathvector-mrt` binary replays real internet routing table dumps:
- Parses MRT TABLE_DUMP_V2 format (RFC 6396); handles `.mrt` and `.mrt.gz` via `flate2`.
- Opens a real TCP BGP session to pathvectord (OPEN → KEEPALIVE → Established).
- Batches NLRIs with identical attribute bytes into single UPDATE messages up to the
  RFC 4271 4096-byte limit — matching real peer behaviour.
- Polls `watch_routes` gRPC stream until prefix count stabilises; reports convergence time
  and final RIB count. `list_all_routes` helper added to `DaemonClient` for paginated reads.
- Benchmark on M2 Max against RIPE RIS full table (1,133,510 IPv4 prefixes): 343,920
  prefixes/sec announcement throughput; 3.70 s RIB convergence; 7.00 s end-to-end.

`just mrt ./latest-bview.gz` recipe added. Parser and speaker have 7 unit tests.

### [pathvectord, pathvector-client] Cursor-based pagination for `ListRoutes`

`ListRoutesRequest` gains `page_size` and `page_token` fields. `page_size=0` (default)
returns all routes for backward compatibility; non-zero enables cursor-based pagination
sorted by prefix string. `DaemonClient::list_all_routes` issues paginated requests in a
loop (`PAGE_SIZE=5000`) to work around the 4 MB tonic limit. Test:
`test_list_routes_pagination_returns_all_routes_across_pages`.

### [pathvectord] gRPC correctness — `originate_route` validation and upsert semantics

`parse_originate_request` now rejects `next_hop = 0.0.0.0` with `INVALID_ARGUMENT` — an
unspecified address is never a valid BGP forwarding next-hop (RFC 4271 §5.1.3). Test:
`test_parse_originate_request_rejects_unspecified_next_hop`.

Upsert semantics documented in proto: re-originating the same prefix silently replaces the
previous route (HashMap::insert). Test: `test_originate_route_upsert_replaces_previous_route`.

### [pathvectord] Documentation — per-crate READMEs overhaul

Full documentation pass producing first-class per-crate READMEs for all 9 crates.
`pathvectord/README.md` absorbs `DAEMON.md` + `LOCAL_INTEROP.md` with field-by-field config
explanations and GoBGP/BIRD interop guide. Adds "Behavior on restart" section documenting
`RTPROT_BGP` stale-route cleanup. `docs/` mdBook and `CLI.md`, `DAEMON.md`, `PERFORMANCE.md`,
`LOCAL_INTEROP.md` removed; `book.toml` removed. `CONTRIBUTING.md` gains "Which crate do I
edit?" routing table. `e2e/` renamed to `pathvector-e2e/`, `fuzz/` to `pathvector-fuzz/`.

### [pathvector-rib] Memory optimization — `rib-memory-opt` branch

Stress benchmark (release profile, Apple M2 Max, synthetic uniform routes):

| Table size | pathvectord RSS | GoBGP RSS | Ratio |
|---|---|---|---|
| 10k  | 11.8 MB  | 51.7 MB  | pathvector 4.4× less |
| 100k | 66.8 MB  | 133.2 MB | pathvector 2.0× less |
| 500k | 461.2 MB | 465.4 MB | ~equal |
| 900k | 515.2 MB | 792.4 MB | pathvector 35% less |

Per-route at 900k: **0.57 KB/route** (pathvectord) vs **0.88 KB/route** (GoBGP). The RSS
plateau between 500k–900k (+54 MB for 400k additional routes) confirms attribute interning /
Arc-sharing is effective — real internet routes converge onto a small set of shared
attribute sets as the table grows. No further memory audit planned unless profiling on a
real multi-peer internet table (not synthetic) reveals a regression.

## 2026-06-16

### [pathvectord] RFC 4271 correctness audit — fixes (A, B, H, J)

**A — AS_PATH loop detection** (`pathvectord/src/daemon.rs`)
`handle_update` checks `as_path.contains(local_as)` and silently drops announcements
(not withdrawals), matching RFC 4271 §6.3 SHOULD. Tests: `test_as_path_loop_detection_*` (4 tests).

**B — Mandatory attribute presence** (`pathvectord/src/daemon.rs`)
`handle_update` now detects absent ORIGIN/AS_PATH/NEXT_HOP and returns a `NotificationMessage`
with `error = UpdateMessage(MissingWellKnownAttribute)` and `data = [attr_type]` (RFC 4271
§6.3 MUST). The full message is threaded through the event loop →
`SessionCommand::Notification` → FSM → wire. Tests: `missing_origin_returns_notification_*`,
`missing_as_path_returns_notification_*`, `missing_next_hop_*`,
`withdraw_only_update_no_notification_for_missing_attrs`,
`all_mandatory_attributes_present_no_notification`,
`malformed_update_missing_origin_sends_notification_to_session`.

**H — MRAI** (`pathvectord/src/daemon.rs`)
eBGP MRAI (30 s window) implemented via per-NLRI per-peer `mrai_last_sent` / `mrai_pending`
maps in `DaemonState`. Suppression converts `PrefixDecision::Announce` → `NoChange` after
`propagate_prefix` updates AdjRibOut (RIB is always correct; only wire transmission is
deferred). A half-MRAI flush timer calls `flush_mrai_pending` on elapsed NLRIs using
`partition()` — avoids the `max()` bug. Tests: `mrai_suppresses_ebgp_announcement_within_window`,
`mrai_passes_after_window_elapsed`, `has_mrai_pending_*` (2), `flush_mrai_pending_clears_elapsed_pending`,
`mrai_withdrawal_bypasses_suppression`. iBGP MRAI (RFC 4271 SHOULD ≥5 s) deferred.

**J — AS_TRANS / AS4_PATH for 2-byte-only peers (RFC 6793)** (`pathvectord/src/outbound.rs`)
`route_to_attributes` accepts `peer_four_byte: bool`. When `false`,
`AsPath::downgrade_for_two_byte_peer()` substitutes 4-byte ASNs with AS_TRANS (23456) in the
wire AS_PATH and appends AS4_PATH (type 17, flags 0xC0 optional+transitive) last per RFC 6793
§4. Tests: `two_byte_asns_to_two_byte_peer_no_trans_no_as4_path`,
`four_byte_asn_to_two_byte_peer_inserts_trans_and_as4_path`,
`four_byte_asn_to_four_byte_peer_no_trans_no_as4_path`,
`as4_path_is_last_attribute_for_two_byte_peer`,
`all_four_byte_asns_to_two_byte_peer_full_trans_substitution`.

### [pathvectord] RFC 4271 correctness audit — fixes (C, D, F, G, K)

**C — NEXT_HOP validation** (`pathvectord/src/daemon.rs`)
`is_valid_next_hop_v4` rejects 0.0.0.0, loopback, multicast (224.0.0.0/4), and broadcast.
Own-address check deferred (FIB oracle reachability gates this anyway).
Tests: `test_invalid_next_hop_*` (3) + `test_valid_next_hop_is_accepted`.

**D — BGP Identifier validation** (`pathvector-session/src/fsm/mod.rs`)
`validate_open` rejects loopback, multicast, and broadcast BGP IDs in addition to 0.0.0.0.
Tests: `test_multicast_bgp_id_rejected`, `test_broadcast_bgp_id_rejected`.

**F — ORIGINATOR_ID and CLUSTER_LIST stripping for eBGP** (`pathvectord/src/outbound.rs`)
`route_to_attributes` strips both when `peer_type == External` (RFC 4456 §8 MUST).
Tests: `test_route_to_attributes_ebgp_strips_originator_id_and_cluster_list`,
`test_route_to_attributes_ibgp_preserves_rr_attributes`.

**G — MED stripping for eBGP** (`pathvectord/src/outbound.rs`)
`route_to_attributes` strips MED when `peer_type == External` (RFC 4271 §5.1.4 SHOULD NOT).
Tests: `test_route_to_attributes_ebgp_strips_med`, `test_route_to_attributes_ibgp_preserves_med`.

**K — IPv6 routes gated on Multi-Protocol capability** (`pathvectord/src/daemon.rs`)
`on_established` gates IPv6 full-table dump and `propagate_to_all_peers_v6` on
`peer_capabilities.contains(MultiProtocol(IPV6_UNICAST))`.
Tests: `test_ipv6_route_not_propagated_to_non_ipv6_capable_peer`,
`test_ipv6_full_table_dump_not_sent_to_non_ipv6_capable_peer`.

**O — Panic/unwrap audit: clean pass**
No crash vectors reachable from peer input, gRPC clients, or config files. All `expect()`
calls in production code are true invariants protected by prior validation guards.

### [cross-cutting] Test coverage expansion (98.0% workspace)

Workspace unit test count increased from ~320 to 376. Key additions:
- `pathvectord/src/fib.rs`: `FibWrite` trait + `MockFibWriter`, `FibManager::new()` spawn
  loop, `DaemonOracle` V6WithLinkLocal branch, V6 error path via `failing_v6()`
- `pathvectord/src/grpc.rs`: `route_v6_to_proto` V4/V6WithLinkLocal/aggregator branches,
  `parse_nlri_v6` error, `originate_route_v6` Incomplete origin, peer-filter mismatch branches
- `pathvectord/src/outbound.rs`: `propagate_prefix`/`_v6` split-horizon and iBGP filtered
  paths, batch-overflow flush tests (fixed 1 000 → 1 500 NLRI threshold), `AtomicAggregate`
  and `AS4_PATH` v6 attr tests
- `pathvector-sys/src/fib/stub.rs`: UFCS tests for all four `FibWrite` trait impl bodies

### [pathvectord] macOS interop fix — DaemonOracle gated on Linux

`KernelFib` on macOS is a no-op stub with an always-empty `FibSnapshot`. Without this fix
`DaemonOracle` marked every peer-learned next-hop unreachable, so `select_best_with_oracle`
excluded all routes from `LocRib.best` — routes were accepted and counted but never selected,
making them invisible in `pv route list` and the dashboard.

Fix: gate oracle construction and `set_oracles()` on `#[cfg(target_os = "linux")]`. On
non-Linux the default `AlwaysReachable` oracle remains in place. No behavioural change on Linux.

---

## 2026-06-15

### [pathvector-rib, pathvectord] DaemonOracle wired into best-path selection (Gap 2)
`DaemonOracle` (wrapping `KernelOracle` → live `FibSnapshot`) is now the oracle used for
all LocRib operations. `DaemonState` holds `oracle_v4/v6: Arc<dyn NextHopOracle + Send + Sync>`,
initialized to `AlwaysReachable` and replaced by `set_oracles()` in `run_with()` before the
event loop starts. All LocRib methods (`insert`, `withdraw`, `withdraw_peer`, `recompute_all`)
receive `Arc::clone(&self.oracle_v4/v6)`. `select_best_with_oracle` filters unreachable
next-hops (step 1) and uses `igp_metric` for the step-8 tiebreaker. RFC 4271 §9.1 steps 1
and 8 are fully live at runtime.

### [pathvector-sys, pathvectord] Stale BGP route cleanup on restart (Gap 4)
`KernelFib::stale_bgp_routes()` dumps all `RTPROT_BGP` routes from the kernel table at daemon
startup. `withdraw_stale_bgp_routes` (extracted `pub(crate) async fn` in `daemon.rs`) iterates
the results and issues `RTM_DELROUTE` via `FibWriter` before the BGP event loop begins. At
startup the Loc-RIB is empty so every kernel BGP route is stale from a previous run; no
convergence signaling is needed. Matches BIRD's `krt` protocol startup behaviour. Two portable
unit tests cover the empty-list no-op and absent-route (ESRCH-suppressed) paths; full
integration coverage deferred to Gap 8 e2e test.

### [pathvector-sys, pathvectord] BGP route feedback loop fix (Gaps 3 & 7 follow-up)
`RTPROT_BGP` routes excluded from `FibSnapshot` (`parse_v4`/`parse_v6` return `None` for BGP
protocol). `apply_new`/`apply_del` return `bool`; `change_tx` fires only on actual snapshot
changes. `fib_change_rx` wired into `run_event_loop` via `watch::Receiver<()>`. `on_fib_change`
on `DaemonState` calls `recompute_all` over both RIBs, pushes diffs to `FibManager`, propagates
changed prefixes to peers. Completes the IGP-change → BGP-reconvergence path.

### [pathvector-rib, pathvectord] LocRib pure data structure + recompute_all (Gaps 2 & 3)
`LocRib` oracle parameter removed from construction; `recompute_best` now takes
`oracle: &dyn NextHopOracle` directly. `recompute_all` iterates all candidates, snapshots
before/after, returns only actual `BestPathChange` entries. `rib_recompute_all_v4/v6` wrappers
on `DaemonState` handle the `Arc::clone` indirection.

## 2026-06-14

### [e2e] BIRD 2 interoperability
BIRD 2 interoperability is fully implemented. `e2e/Dockerfile.bird`, `e2e/fixtures/bird.conf`,
and `BirdHarness` in `e2e/src/lib.rs` are all in place. Eight e2e tests pass against BIRD:

- `bird_static_route_appears_in_pathvectord_rib`
- `bird_multiple_static_routes_appear_in_pathvectord_rib`
- `pathvectord_originated_route_reaches_bird`
- `pathvectord_ebgp_next_hop_is_session_local_addr_not_router_id`
- `bird_route_has_correct_peer_address`
- (additional session + route lifecycle tests)

This work also surfaced and fixed RFC 4271 §5.1.3 bug: pathvectord was advertising the
BGP router ID (`bgp_id`) as the eBGP NEXT_HOP instead of the TCP session's local interface
address. BIRD rejected the routes; GoBGP silently accepted them. Fix: the TCP
`local_addr()` is now threaded through `Session<T>` → `SessionInfo` → `on_established`
→ `RibSnapshot::local_addrs` and used as the NEXT_HOP in `prepare_outbound`.

### [e2e] FRR (FRRouting) interoperability
FRR interoperability is fully implemented. 8 tests pass across `frr_session.rs` and
`frr_routes.rs` (session, peer state, list_peers, route inbound, multiple routes,
route outbound, NEXT_HOP §5.1.3, peer address attribution). FRR confirmed that
pathvectord's NEXT_HOP rewrite is correct end-to-end with a second strict peer.

**FRR config gotchas (recorded for future test work):**
- `no bgp network import-check`: FRR 8.x will not advertise `network` statements
  unless the prefix is present in the kernel FIB. This flag bypasses that check,
  which is required in a container where no kernel routes are installed.
- `no bgp ebgp-requires-policy`: FRR 8.x enforces explicit import/export policy
  on eBGP sessions by default (similar to RFC 8212). Must be disabled for simple
  test configs that don't configure per-session policy.
- `--privileged` Docker flag required: `bgpd` calls `cap_set_proc` for
  `CAP_SYS_ADMIN` during startup for netlink access. `--cap-add=NET_ADMIN` alone
  is insufficient on Docker Desktop (macOS); `--privileged` is needed.
- `frrinit.sh start` exits immediately (starts daemons in background). The
  container CMD must keep PID 1 alive (`|| sleep infinity`) to prevent Docker
  from killing the daemons when the init script exits.

### [pathvector-rib] Criterion benchmark suite
`pathvector-rib` has three criterion benchmark groups (`select_best`, `loc_rib_insert`,
`outbound_pipeline`). Baseline on M2 Max:

| Benchmark | Small | Medium | Large |
|---|---|---|---|
| `select_best` | 4.9 ns (2 candidates) | 35 ns (10) | 526 ns (100) |
| `loc_rib_insert` | 309 ns (10k prefixes) | 293 ns (100k) | 802 ns (500k) |
| `outbound_pipeline` (minimal) | 242 ns (1 peer) | 1.61 µs (10) | 8.59 µs (50) |
| `outbound_pipeline` (dense) | 387 ns (1 peer) | 2.64 µs (10) | 14.4 µs (50) |

Run with `cargo bench -p pathvector-rib`. HTML reports in `target/criterion/`.

### [pathvector-rib] Route reflector support (RFC 4456)
Full RFC 4456 route reflector implementation:
- `ORIGINATOR_ID` (type 9) and `CLUSTER_LIST` (type 10) codec in `pathvector-session`
- `Route<A>` carries both fields through the RIB
- `is_rr_client = true` in peer config + optional `cluster_id` in daemon config
- Inbound: loop detection, ORIGINATOR_ID set on first reflection, CLUSTER_LIST prepend
- Outbound: ORIGINATOR_ID / CLUSTER_LIST included in reflected UPDATE attributes
- Split-horizon: client→client, client↔non-client reflect; non-client→non-client blocked
- 6 new unit tests covering all split-horizon cases and attribute encoding

### [pathvectord / pathvector-sys] FIB integration — IPv6 write path
`FibWriter` has `install_v6` / `withdraw_v6`. `FibManager` has `apply_v6`.
`handle_update` returns `(Vec<BestPathChange<Ipv4Addr>>, Vec<BestPathChange<Ipv6Addr>>)`
and dispatches both families; `on_terminated` and `originate_routes_v6` likewise.

### [pathvectord / pathvector-sys] FIB — RTM_DELROUTE ESRCH silenced
`withdraw_route_v4` and `withdraw_route_v6` both treat `NetlinkError` with code `-3`
(ESRCH) as `Ok(())`.

### [pathvectord / pathvector-sys] FIB — fib_table and fib_metric configurable
`DaemonConfig` has `fib_table: u32` (default 254) and `fib_metric: u32` (default 20);
both are threaded through to `FibWriter::new` and `KernelFib::new`.

### [pathvectord] FIB integration — unit tests for FibManager
10 unit tests cover `apply_v4` (announced/withdrawn/unchanged/no-next-hop), `apply_v6`
(announced/withdrawn/unchanged), and all three `DaemonOracle` `NextHop` variants.
Tests use `FibManager::from_sender` (module-private) to construct without spawning.

---

## 2026-06-13

### [pathvector-session] MD5 authentication (RFC 2385)
`md5_password: Option<String>` TOML field → `SessionConfig` → `apply_tcp_md5sig`
(Linux `setsockopt TCP_MD5SIG`) on the outbound `TcpSocket` before `connect()` and on
the BGP listener socket after `bind()`. No-op with `warn!` on non-Linux (macOS dev).
IPv6 peer MD5 deferred.

### [docs] MD5 interop and testing documentation
Added MD5 interop recipe to `LOCAL_INTEROP.md` and refreshed `TESTING.md` with MD5
safety section, `pathvector-sys` proptest table, and full 41-test e2e scenario table.

### [pathvectord] on_route_update / set_import_default RouteEvents emission
Routes that change best-path during `on_route_update` or `set_import_default` now emit
`RouteEvent`s to the broadcast channel so the dashboard and watch subscribers see live
updates without a reconnect.

---

## 2026-06-12

### [pathvectord] IPv6 RIB — dual-stack
Full dual-stack BGP. Inbound: parallel `LocRib<Ipv6Addr>` / `AdjRibIn<Ipv6Addr>`
tables in `DaemonState`; `handle_update` routes `AfiSafi::IPV6_UNICAST`
MP_REACH_NLRI and MP_UNREACH_NLRI to them; `sync_received` counts both AFIs;
`on_established` resets v6 AdjRibIn; `on_terminated` withdraws v6 routes.
Outbound: parallel `AdjRibOut<Ipv6Addr>` per peer; `propagate_prefix_v6` applies
`prepare_outbound_v6` (AS_PATH prepend + NEXT_HOP rewrite for eBGP);
`flush_updates_v6` packs MP_UNREACH_NLRI and MP_REACH_NLRI UPDATE messages;
`propagate_to_all_peers_v6` wires the full pipeline; `on_established` sends a
v6 full-table dump; `on_route_update` propagates affected v6 NLRIs.
Config: `local_ipv6: Option<Ipv6Addr>` in `DaemonConfig` — required for eBGP
next-hop rewrite (iBGP is pass-through and works without it).
Capability: `MultiProtocol(IPV6_UNICAST)` advertised in OPEN.
gRPC: `list_routes` and `watch_routes` include v6 routes via `route_v6_to_proto`.
IPv6 import policy is accept-all; per-AFI policy config is deferred.
Tests: 10 new unit tests covering announce, withdraw, AdjRibIn storage, mixed
v4+v6 UPDATE, eBGP next-hop rewrite, eBGP suppression without `local_ipv6`,
withdraw-on-disappear, full-table dump on Established, end-to-end propagation.

### [pathvectord] IPv6 import policy (RFC 8212 parity)
`import_policies_v6: HashMap<Ipv4Addr, Policy<Route<Ipv6Addr>>>` added to
`DaemonState`, initialized with the same `DefaultAction` as `import_policies`
(Reject for eBGP, Accept for iBGP per RFC 8212). `handle_update` applies BLACKHOLE
check + `policy_v6.evaluate()` to all IPv6 announcements.
Test: `test_rfc8212_ebgp_ipv6_reject_without_policy` verifies eBGP routes are
rejected and stored in AdjRibIn for soft-reconfig.

### [e2e] IPv6 interoperability (GoBGP)
Three new e2e tests confirm the full IPv6 wire path against GoBGP 4.6.0:
- `routes.rs::announced_v6_route_appears_in_rib` — GoBGP announces `2001:db8::/32` via
  MP_REACH_NLRI; pathvectord installs it; `get_best_route` returns it with correct attributes
- `routes.rs::withdrawn_v6_route_removed_from_rib` — GoBGP withdraws via MP_UNREACH_NLRI;
  pathvectord removes it from LocRib_v6
- `outbound.rs::originated_v6_route_propagates_to_gobgp` — pathvectord originates
  `2001:db8:1::/48`; GoBGP receives it via MP_REACH_NLRI with NEXT_HOP = `2001:db8::2`
  (eBGP rewrite from `local_ipv6`)
Also fixed: `get_best_route` gRPC handler now queries `loc_rib_v6` for IPv6 prefixes;
`originate_route`/`originate_routes` dispatch to `originate_route_v6` for IPv6 prefixes.

### [pathvectord] Split main.rs into daemon.rs + outbound.rs
The 5865-line file was split into three modules:
- `src/main.rs` (31 lines) — binary entry point only
- `src/daemon.rs` (5240 lines) — `DaemonState`, `RibSnapshot`, `handle_update`,
  `reapply_import_policy`, `run`, `run_bgp_listener`, and all daemon/event/prop tests
- `src/outbound.rs` (605 lines) — all outbound pipeline functions (`propagate_prefix*`,
  `flush_updates*`, `route_*_to_attributes*`) + their unit and property tests
All 214 unit tests pass; `cargo clippy -D warnings` is clean.

### [pathvector-rib / pathvectord] RibView seam
`pathvector-rib` now exports a `RibView<A>` trait with a single
`best(&self, nlri) -> Option<&Route<A>>` method. `LocRib<A>` implements it.
`propagate_prefix` in `pathvectord` is now generic over `impl RibView<Ipv4Addr>` instead
of taking `&LocRib<Ipv4Addr>` directly. A `StubRibView(Option<Route<Ipv4Addr>>)` test
double in `pathvectord`'s test module (3 tests) demonstrates that the Update-Send Process
can be driven with injected best routes — no RIB construction or peer setup required.

### [pathvector-rib / pathvectord] Outbound NLRI batching proptest coverage
Four proptests covering `flush_updates` (IPv4) and `flush_updates_v6` (IPv6) in
`outbound::prop_tests`:
`prop_flush_updates_no_message_exceeds_max_len`, `prop_flush_updates_all_announces_sent`,
`prop_flush_updates_all_withdrawals_sent`, `prop_flush_updates_v6_no_message_exceeds_max_len`.

### [pathvector-client] Streaming mock clients
`MockDaemonClient::peer/route_events` queues implemented; `watch_routes` and `watch_peers`
return configurable event streams for test use. `BoxStream<T>` type alias exported from
`pathvector-client`.

---

## 2026-06-11

### [pathvector] Dashboard — replace polling with streaming
`run_dashboard` now subscribes to `WatchPeers` and `WatchRoutes` streaming RPCs before
entering raw mode. A `spawn_blocking` thread bridges crossterm's blocking keyboard poll
into the async `tokio::select!` loop alongside `peer_stream.next()` and
`route_stream.next()`. `DashboardState::apply_peer_event` and `apply_route_event` are
pure state-mutation methods that upsert / remove entries in-place. The status bar shows
`● Live` (green) instead of a stale timestamp; connection errors replace the live
indicator with the error string. `MockDaemonClient` grows `watch_routes`/`watch_peers`
impls returning empty streams. 15 unit tests cover all event variants and error paths.
`BoxStream<T>` type alias exported from `pathvector-client` allows naming the stream type
in bindings, struct fields, and `dyn` contexts. `DaemonClient` trait extended with
`watch_routes` and `watch_peers`.

**Remaining dashboard gap:** `last_error` is a single `Option<String>` so two simultaneous
failures (one from each stream) overwrites the first error. In practice both streams fail
together ("daemon down") so the second message is equally informative. Fix requires UI
layout decision; deferred.

### [pathvectord] Connection collision detection
`FsmInput::CollisionDetected` resets the FSM to Active without emitting
`SessionTerminated` (no RIB churn). The transport layer compares `local_bgp_id` vs
`peer_bgp_id` (from the stored peer OPEN) and either adopts the incoming stream or drops
it. `pathvectord` spawns a `TcpListener` on `bgp_port` (default 179, configurable) and
routes accepted connections to per-peer sessions via `SessionCommand::IncomingConnection`.
Tests: `test_collision_detected_in_open_sent/open_confirm_resets_to_active`,
`test_collision_local_wins_adopts_incoming`, `test_collision_peer_wins_keeps_outbound`.

### [pathvectord] RibSnapshot split — eliminate gRPC/event-loop read contention
`DaemonState` now holds `rib: Arc<RibSnapshot>`. gRPC handlers call `snapshot()` to clone
the `Arc` (O(1) atomic increment) and release the outer lock before iterating. The event
loop mutates via `Arc::make_mut` — zero-cost when refcount is 1, copy-on-write only when
a gRPC call is in-flight. See `DECISIONS.md` for full rationale.

**Known concern — CoW under long-lived gRPC streams**: `Arc::make_mut` is zero-cost
when refcount == 1 (the common case). The O(N) clone only fires when a snapshot `Arc`
is held while the event loop mutates state. Streaming handlers must never hold a snapshot
`Arc` across `await` points.

### [e2e] Origination e2e test suite
12 tests in `e2e/tests/origination.rs` covering originated route propagation to GoBGP,
batch origination, withdrawal, idempotent re-origination, attribute preservation
(communities, local_pref, med), blackhole community (RFC 7999), coexistence with
peer-learned routes, and no-op withdrawal of unknown prefix.

---

## 2026-06-10

### [pathvector-session] RFC 7606 — Revised UPDATE error handling
`UpdateDecodeOutcome::Partial` replaces the flat `Err(CodecError)` path for
per-attribute errors. `BgpMessage::MalformedUpdate` carries the cleaned UPDATE
plus per-attribute `AttributeDecodeError` entries. The transport layer applies
the RFC 7606 §5 policy table: treat-as-withdraw (ORIGIN, AS_PATH, NEXT_HOP,
LOCAL_PREF, MP_REACH_NLRI) or attribute-discard (all optional non-mandatory
attributes). Duplicate type codes in a single UPDATE are detected and treated as
withdraw (RFC 7606 §7.3). Good attributes in the same UPDATE survive alongside a
discarded attribute. `make_treat_as_withdraw` converts announced NLRIs and any
decoded MP_REACH_NLRI prefixes into proper withdrawals. The session stays up in
all cases; malformed-attribute events are `tracing::warn!`-logged with type code,
detail, and RFC 7606 policy. See RFC_REQUIREMENTS.md §RFC 7606 for full coverage.

### [pathvector-session] ROUTE-REFRESH receive guard
ROUTE-REFRESH received in `Established` is now gated on capability negotiation.
If both sides advertised `RouteRefresh` during OPEN, the message is accepted
(session stays up; full re-advertisement is deferred as a future item).
If not negotiated, the FSM sends FSM Error subcode 3 and tears down the
session. The send direction is a no-op because pathvector never initiates
ROUTE-REFRESH today.
Tests: `test_route_refresh_with_capability_is_accepted`,
`test_route_refresh_without_capability_sends_fsm_error_subcode_3`.

### [pathvector-session] FSM error subcodes 1/2/3
Added `FsmErrorOpenSent`, `FsmErrorOpenConfirm`, `FsmErrorEstablished` variants
to `NotificationError` (wire: code 5, subcodes 1/2/3). The three `_ => vec![]`
wildcards in `on_open_sent`, `on_open_confirm`, and `on_established` now each
send the correct NOTIFICATION and tear down the session when an unexpected
message type arrives.
Tests: `test_unexpected_message_in_open_sent_sends_fsm_error_subcode_1`,
`test_unexpected_message_in_open_confirm_sends_fsm_error_subcode_2`,
`test_unexpected_message_in_established_sends_fsm_error_subcode_3`.

### [pathvector-session] RFC 8654 Extended Message
`BgpCodec` is now stateful; `set_extended_message(true)` raises the frame limit to
65535 bytes after both peers negotiate `Capability::ExtendedMessage` (code 6).
`MAX_LEN`/`MAX_LEN_EXTENDED` are the single source of truth shared between the
framing and message layers. `BgpMessage::decode_with_limit` added for explicit
limit control. Two proptests cover large-message roundtrip and rejection without
negotiation. The transport `execute` loop calls `set_extended_message` in the
`SessionEstablished` arm.

### [pathvector-session] RFC 6286 AS-wide unique BGP ID
`validate_open` rejects iBGP peers that present the same BGP ID as the local speaker
with `NOTIFICATION(BadBgpIdentifier)`; eBGP peers are exempt per the RFC. Two unit
tests cover the accept/reject paths.

### [pathvector-session] RFC 5492 Unsupported Capability
`required_capabilities: Vec<Capability>` added to `FsmConfig`/`SessionConfig`.
`validate_open` emits `NOTIFICATION(UnsupportedCapability)` with capability codes
encoded in the data field when a required capability is absent. Retry after stripping
rejected capabilities is deferred.

### [pathvectord] BLACKHOLE community discard action (RFC 7999)
`handle_update` now checks `raw.communities.iter().any(|c| c.is_blackhole())` before
the import-policy step. BLACKHOLE-tagged routes are stored in `AdjRibIn`
(soft-reconfig visibility) but never installed in `LocRib` or advertised outbound.
Three unit tests cover: not-installed, stored-in-AdjRibIn, and non-BLACKHOLE routes
unaffected.

### [pathvector-client] Route origination API
`originate_route`, `originate_routes`, `withdraw_originated_route`,
`withdraw_originated_routes`, `list_originated_routes` added to `DaemonClient` trait
and implemented on `PathvectorClient`. `OriginateRouteParams` domain type in
`types.rs`; `From` impl in `convert.rs`.

### [pathvector-client] Streaming watch RPCs
`watch_routes(peer: Option<&str>)` and `watch_peers()` as methods on `PathvectorClient`
returning `impl Stream<Item = Result<RouteEvent/PeerEvent, ClientError>>`. Not included
in `DaemonClient` trait (stream types are too complex to mock generically).
`RouteEvent`, `RouteEventType`, `PeerEvent`, `PeerEventType` domain types added.

### [pathvector-client] Route.peer_address Optional
Changed from `IpAddr` to `Option<IpAddr>`; `None` means locally originated route.
`convert.rs` maps proto `"local"` string → `None`; output rendering shows `"local"` for
CLI/dashboard.

### [cross-cutting] Test coverage 97%+ workspace-wide
Comprehensive unit and integration tests added across all crates. Key gaps closed:
grpc origination handlers, watch stream deadlock fix (drop sender before polling),
lib.rs watch conversion closures, transport retry/ExtendedMessage/MpReachNlri paths.
All clippy `-D warnings` errors resolved.

### [pathvectord] Route origination gRPC service and streaming RPCs
`OriginationService` is live on `pathvectord` with five RPCs: `OriginateRoute`,
`OriginateRoutes` (batch), `WithdrawOriginatedRoute`, `WithdrawOriginatedRoutes` (batch),
and `ListOriginatedRoutes`. Routes are injected directly into `LocRib` under the synthetic
`LOCAL_ORIGIN_PEER` (`0.0.0.0`) key, bypassing import policy; export policy still applies
per peer. A single `propagate_to_all_peers` call after the batch completes means N routes
produce ~2 BGP UPDATE messages per peer regardless of N.

`WatchRoutes` and `WatchPeers` streaming RPCs are live on `RibService` and `PeerService`.
Snapshot-then-stream: subscribe to broadcast channel first (no race), send current state as
`CURRENT` events, send `END_INITIAL` sentinel, then stream live deltas. `broadcast::channel`
capacity 1024; slow subscribers receive `RecvError::Lagged` and must reconnect.

---

## 2026-06-09

### [pathvectord] Advertise MultiProtocol(IPv4_UNICAST) capability
Added `Capability::MultiProtocol(AfiSafi::IPV4_UNICAST)` to the session config.
Brings the OPEN into RFC 4760 compliance and causes GoBGP to send IPv4 routes via
MP_REACH_NLRI, exercising the MP code path against a real peer for the first time.
Also the mandatory first step before advertising IPv6 capability.

### [pathvectord] Soft reconfiguration → export propagation
Added `DaemonState::set_import_default` and `set_export_default` methods that update the
relevant policy, call `reapply_import_policy`, and immediately propagate any Loc-RIB
changes to all established peers via `propagate_prefix`. Exposed as `SetImportDefault` /
`SetExportDefault` gRPC RPCs in the new `PolicyService`. Two soft-reconfig e2e tests
confirm the full chain (`e2e/tests/policy.rs`:
`soft_reconfig_import_accept_installs_route`,
`soft_reconfig_export_accept_propagates_to_sink`).

### [pathvector] CLI tool (pathvector crate)
Implemented as `pathvector/` workspace member. Subcommands: `peer list`, `peer get`,
`route list [--peer]`, `route best`, `route candidates`, `policy set-import`,
`policy set-export`, `route originate`, `route withdraw`, `route list-originated`,
`watch routes [--peer]`, `watch peers`, and `dashboard` (live ratatui TUI). Global
`--address` flag + `PATHVECTOR_ADDRESS` env var select the daemon endpoint. `watch routes`
and `watch peers` stream events to stdout until Ctrl-C using `tokio::select!` on the
stream and `tokio::signal::ctrl_c()`.

### [pathvectord] gRPC management API
`PeerService`, `RibService`, and `PolicyService` are live. Proto schema at
`proto/pathvector/v1/management.proto`. See DAEMON.md for the full operational guide
and `grpcurl` examples; see CLI.md for the `pathvector` CLI reference.

### [e2e] End-to-end test suite (Phase 5)
Both gobgpd and pathvectord run as Linux containers on an isolated Docker bridge network
per test. BGP (port 179) is container-to-container — the macOS Docker Desktop TCP proxy
never touches it. Only pathvectord's gRPC port is mapped to the host for
`PathvectorClient`.

20 tests passing across 4 files:
- `routes.rs` (6), `session.rs` (6), `outbound.rs` (4), `policy.rs` (4)

Outbound advertisement tests: `TwoPeerHarness` in `e2e/src/lib.rs`; four tests in
`e2e/tests/outbound.rs` cover: single prefix propagation, multi-prefix, withdrawal,
and management-API visibility.

Import/export-policy reject tests (RFC 8212): `Harness::new_rfc8212()` configures
pathvectord with no policy on the peer; `TwoPeerHarness::new_no_export_policy()`
configures import-accept + no export. Four tests in `e2e/tests/policy.rs` prove both
directions.

### [e2e] GitHub Actions e2e workflow
Separate `e2e` job in `.github/workflows/ci.yml` on `ubuntu-latest` (Docker
pre-installed). Uses `docker/setup-buildx-action` + `docker/build-push-action` with
`type=gha` layer caching (separate scopes for `gobgpd` and `pathvectord` images).
GoBGP image is a cache hit on repeat runs. `test` and `msrv` jobs now pass
`--exclude pathvector-e2e` so the crate is not exercised without its required images.
A `.githooks/pre-push` hook (installed via `just install-hooks`) runs `just e2e`
locally before each push.

### [cross-cutting] try_send stall detection fixed
`propagate_prefix` now returns `bool`; a `false` return means the channel was full.
The three `DaemonState` event methods collect stalled peers into `self.stalled_peers`.
After each event, `run()` sends `SessionCommand::Stop` to each stalled session via a
retained `stop_senders` map (populated from a new `SessionHandle::stop_sender()`
method). The session re-establishes and `on_established` performs a fresh full-table
dump from a clean `AdjRibOut`, restoring a consistent peer view. Overflow is logged
at `ERROR`.

### [pathvectord] Docker image
`e2e/Dockerfile.pathvectord` is a multi-stage build: `rust:1.88-slim-bookworm` builder
(with `protobuf-compiler`), `debian:bookworm-slim` runtime (with `netcat-openbsd` for
HEALTHCHECK). Config file is bind-mounted at container start. gRPC port 51200 is
exposed and mapped dynamically by testcontainers. Built via `just e2e-images`.

### [pathvector-rib] best-path proptests (Phase 2)
Step-by-step isolation proptests in `pathvector-rib/src/best_path.rs::prop_tests`:
- `prop_select_best_winner_has_highest_local_pref` — winner LP ≥ all others (step 2)
- `prop_select_best_missing_local_pref_treated_as_100` — None → 100 default (step 2)
- `prop_select_best_winner_has_shortest_as_path` — winner len ≤ all others (step 4)
- `prop_select_best_winner_has_lowest_origin` — winner origin ≤ all others (step 5)
- `prop_select_best_winner_has_lowest_med` — winner MED ≤ all others, None=0 (step 6)
- `prop_select_best_ebgp_beats_ibgp` — eBGP beats iBGP even with lower peer IP (step 7)
- `prop_select_best_lower_peer_ip_wins_on_full_tie` — full-tie tiebreaker (step 10)
- `prop_select_best_non_empty_returns_some`, `prop_select_best_winner_is_in_candidates`
  (structural invariants)
- LocRib, AdjRibIn, and AdjRibOut structural proptests (insert/withdraw/consistency)

---

## 2026-06-08

### [pathvectord] gRPC server reflection
`tonic-reflection` registered at startup. `grpcurl` now works without `--proto` flags;
`grpcurl -plaintext localhost:50051 list` discovers all services at runtime.

### [pathvectord] IPv4 MP_REACH_NLRI / MP_UNREACH_NLRI handling
`handle_update` now processes `MP_UNREACH_NLRI` and `MP_REACH_NLRI` attributes for
AFI/SAFI=IPv4 unicast. Peers that send IPv4 withdrawals or announcements via the
multiprotocol attributes instead of the traditional fields are handled correctly.
Non-IPv4 AFI/SAFIs are logged at DEBUG and skipped.

### [pathvector-client] Self-contained gRPC client library
`PathvectorClient::connect(addr)` — lazy channel construction; no async required.
`list_peers()`, `get_peer(addr)`, `get_best_route(prefix)`, `list_routes(peer_filter)`,
`list_candidates(prefix)`. `TryFrom` conversion layer with explicit error variants:
`InvalidAddress`, `UnknownEnumValue`, `BadExtendedCommunityLen`. Three error types:
`ConnectError`, `ClientError`, `ConvertError`. Optional `serde` feature flag on all
domain types.

---

## Earlier (undated / pre-2026-06-08)

### [cross-cutting] RFC_REQUIREMENTS.md
Download of relevant RFCs, requirement extraction, and compliance checking against each
module. `RFC_REQUIREMENTS.md` tracks every implemented RFC, its requirements, owning
module, implementation status, and verified-by test citations.

### [pathvector-session] Message codec and FSM
- Message codec: OPEN, UPDATE, KEEPALIVE, NOTIFICATION, ROUTE-REFRESH
- NLRI parser: variable-length prefix encoding for IPv4 and IPv6
- MP_REACH_NLRI / MP_UNREACH_NLRI for multiprotocol routes
- 4-byte ASN capability — codec encoding/decoding, `AS_TRANS` substitution in FSM,
  `AS4_PATH` / `AS4_AGGREGATOR` handling
- Graceful Restart and Route Refresh capability — codec parsing and encoding
- BGP FSM: Idle → Connect → Active → OpenSent → OpenConfirm → Established
- Codec error logging in transport — `recv_message` errors surfaced via `tracing::warn!`
- **GoBGP interoperability validated (2026-05-31)** — full session lifecycle confirmed:
  OPEN negotiation, KEEPALIVE exchange, UPDATE announce and withdraw, session teardown
- **Outbound UPDATE send path (2026-06-01)** — `SessionHandle::update_sender()` returns
  a cloneable `mpsc::Sender<UpdateMessage>`. `wait_for_input()` wraps its `select!` in a
  `loop` with a lowest-priority arm that writes outbound UPDATEs directly to the TCP
  framer inline; write failures return `TcpFailed` to the FSM for clean recovery.

### [pathvector-session] Panic safety in build_session_info
`build_session_info` now returns `Option<SessionInfo>`. The `on_open_confirm`
Keepalive arm uses `let...else`: on `None` it logs `tracing::error!`, resets the FSM
to Idle, and returns `[StopHoldTimer, StopKeepaliveTimer, CloseTcpConnection]` — the
same clean teardown as a normal failure, without panicking or leaving stale routes.
Covered by `test_keepalive_in_open_confirm_with_missing_peer_open_resets_to_idle`.

### [pathvector-session] Transport layer mocking via BgpTransport trait
`BgpTransport` is a public trait (RPITIT + `+ Send` bounds) in `transport/mod.rs`.
`FramedBgpTransport` is the production impl wrapping `FramedRead`/`FramedWrite` over
TCP. `Session<T: BgpTransport>` is generic; `spawn()` stays non-generic.
`spawn_with<T: BgpTransport>` injects a pre-built transport (ungated — no
`#[cfg(test)]`) so production integrations can supply their own I/O layer.

### [pathvector-session] Hold timer expiry — active FSM enforcement
The hold timer is fully implemented and wired. `wait_for_input` fires
`HoldTimerExpired` when `hold_deadline` elapses; `on_established` sends
`NOTIFICATION(HoldTimerExpired)`, stops timers, closes TCP, and emits
`SessionTerminated`. KEEPALIVE and UPDATE receipt call `reset_hold_if_active()`.

### [pathvector-session] Codec proptests (Phase 1)
All four message types (OPEN, UPDATE, NOTIFICATION, KEEPALIVE, ROUTE-REFRESH) have
round-trip proptests at both the `BgpMessage::encode/decode` layer and the `BgpCodec`
framing layer. Full capabilities, path attributes, and all `NotificationError`
sub-families are exercised. `prop_decode_never_panics` covers both layers.

### [pathvector-policy] Policy semantics proptests (Phase 3)
- `prop_policy_evaluation_is_deterministic`: same route state evaluated twice always
  produces the same decision.
- `prop_first_match_wins_accept_blocks_later_reject`: a route matched by term N
  (Accept) is never passed to term N+1 (catch-all Reject).
Also covers 8 action invariants (PrependAsPath, Add/Remove/SetCommunities,
SetLocalPref, AnyCondition, ActionSequence).

### [pathvectord] TOML config, session spawning, RIB integration, structured logging
- TOML configuration: `local_as`, `bgp_id`, `hold_time`, per-peer `address`/`port`/`remote_as`
- Session spawning: one `transport::spawn()` task per configured peer, events multiplexed
  into a single channel
- RIB integration: `UpdateMessage` → `Route<Ipv4Addr>` conversion, `LocRib`
  insert/withdraw/peer-teardown
- Structured logging via `tracing` with `RUST_LOG` env-filter support
- **GoBGP interoperability validated (2026-05-31)**
- **Outbound advertisement path (2026-06-01)**

### [pathvectord] Import policy + AdjRibIn + RFC 8212 defaults
`handle_update` evaluates a `Policy<Route<Ipv4Addr>>` per route before `LocRib::insert`;
routes that return `Reject` are dropped. Per-peer default action (`import_default =
"accept"` / `"reject"`) is configurable in TOML; eBGP peers default to `"reject"` (RFC
8212) when omitted, iBGP peers default to `"accept"`. `AdjRibIn` per-peer tables built
at startup and wired through `handle_update`. `reapply_import_policy` re-evaluates all
stored raw routes against a new policy.

### [pathvectord] Panic safety in main event loop
All `expect()` calls in `run()` replaced with `let...else` + `tracing::error!` +
`continue`. Unknown peer IPs now log an error and skip the event rather than panicking
the daemon.

### [pathvector-rib] Longest-prefix-match queries
`LocRib::best` now uses `RouteMap<A, (PeerId, Route<A>)>` (routemap 0.1.2) instead of
`HashMap`. `LocRib::longest_match(addr: A)` exposes O(log n) LPM for forwarding lookups.
Exact-prefix queries (`best`, `best_peer`) use the new `RouteMap::get` added in
routemap 0.1.2.

### [pathvectord] Outbound advertisement path (full BGP speaker)
- `ExportDefault` config enum and per-peer `export_default` field
- Per-peer export policies evaluated via `propagate_prefix` before `AdjRibOut` insertion
- `prepare_outbound` applies eBGP attribute transforms: prepend local AS to `AS_PATH`,
  rewrite `NEXT_HOP` to local BGP ID, strip `LOCAL_PREF`
- `route_to_update` / `withdraw_msg` serialise `AdjRibOut` changes to wire-format
  `UpdateMessage`
- On `Established`: `AdjRibOut` reset, full-table dump to new peer
- On `RouteUpdate`: affected NLRIs propagated to all established peers
- On `Terminated`: snapshot-before-withdraw pattern propagates best-path changes;
  `AdjRibOut` reset for clean reconnect
- Idempotent: `propagate_prefix` compares new route against `AdjRibOut` and sends
  UPDATE/WITHDRAW only when advertised state actually changes

### [cross-cutting] Architecture overview document
`ARCHITECTURE.md` at the workspace root covers crate dependency graph, full inbound and
outbound route paths, session lifecycle events table, management plane lock split
rationale, BgpTransport trait seam, and key design invariants.

### [cross-cutting] CI pipeline
`.github/workflows/ci.yml` has five jobs: `test` (stable), `lint` (clippy + rustfmt,
stable), `msrv` (1.88), `docs` (stable, `-D warnings`), and `fuzz` (nightly, `just
fuzz-smoke`). A `Justfile` at the workspace root provides matching local recipes. All
jobs install `protoc`.

### [cross-cutting] cargo fuzz targets (Phase 4)
Two fuzz targets in `fuzz/fuzz_targets/`:
- `session_framing` — feeds raw `&[u8]` into `BgpCodec::decode`; if the framing layer
  accepts a frame, the round-trip encode/decode is also exercised.
- `session_message` — patches the 2-byte length field so `BgpMessage::decode` receives
  a self-consistent buffer, driving body-parsing for all five message types.

Seed corpus pre-populates valid KEEPALIVE, OPEN, NOTIFICATION, UPDATE, and ROUTE-REFRESH
examples. Both targets compile clean under nightly and ran ~3M executions / 16 seconds
with zero panics on first smoke run.

### [pathvectord] FIB integration — partial (KernelFib, FibWriter, FibManager, DaemonOracle)
`KernelFib` (passive FIB tracker), `KernelOracle`, `FibWriter`
(`RTM_NEWROUTE` / `RTM_DELROUTE`), `DaemonOracle` (`NextHopOracle` impl),
`FibManager` (async write queue). `BestPathChange<Ipv4Addr>` is dispatched from
`on_route_update`, `set_import_default`, `on_terminated`, and
`withdraw_originated_routes`. IPv4 routes are installed into the kernel FIB on
best-path change.

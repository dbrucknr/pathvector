//! End-to-end interop tests proving pathvectord acts as a real BGP
//! Confederation (RFC 5065) Member-AS — not just pass-through/interop with
//! someone else's confederation, and not just the hand-built
//! `UpdateMessage`/`handle_update` unit tests in `pathvectord`'s own test
//! suite.
//!
//! Three real BGP speakers: FRR configured as a fellow confederation
//! Member-AS (FRR is confederation-aware — a plain eBGP speaker would
//! originate routes with an ordinary `AS_SEQUENCE`, not the
//! `AS_CONFED_SEQUENCE` RFC 5065 §5 requires from a fellow Member-AS peer),
//! a genuinely external GoBGP peer, and pathvectord itself. See
//! [`ConfederationHarness`]'s doc comment for the exact AS numbers and
//! topology.

use std::time::Duration;

use pathvector_client::DaemonClient;
use pathvector_e2e::{
    CONFEDERATION_EXTERNAL_AS, CONFEDERATION_EXTERNAL_MED_ROUTE,
    CONFEDERATION_EXTERNAL_NO_EXPORT_SUBCONFED_ROUTE, CONFEDERATION_EXTERNAL_ROUTE,
    CONFEDERATION_FRR_MEMBER_AS, CONFEDERATION_FRR_ROUTE, CONFEDERATION_ID,
    CONFEDERATION_PATHVECTORD_MEMBER_AS, ConfederationHarness, frr_show_route_text, gobgp_rib_text,
    wait_for_frr_rib_entry, wait_for_frr_rib_withdrawn, wait_for_gobgp_rib_entry,
};

/// Both BGP sessions must reach `Established`.
///
/// This is itself part of the interop proof, not just a precondition: the
/// external GoBGP peer's config expects pathvectord's OPEN to carry
/// [`CONFEDERATION_ID`] (RFC 5065 §4), not
/// [`CONFEDERATION_PATHVECTORD_MEMBER_AS`] — a regression in the public_as
/// resolution fixed after external review of PR #51 would make this
/// specific session never establish (GoBGP would reject it as Bad Peer AS),
/// while the FRR session (which legitimately expects the Member-AS) would
/// still come up fine. Asserting both catches exactly that asymmetric
/// failure mode.
#[tokio::test]
async fn confederation_sessions_establish_with_correct_visible_as() {
    // `ConfederationHarness::new` already waits for both sessions to reach
    // Established (panicking with a specific message identifying which
    // session failed and why, if either does not) — reaching this line at
    // all proves the property under test.
    let _h = ConfederationHarness::new().await;
}

/// RFC 5065 §4.1(c): a route originated by the fellow Member-AS (FRR) and
/// relayed by pathvectord to the genuinely external GoBGP peer must have its
/// confederation segment stripped and the AS Confederation Identifier
/// prepended — the external peer must see a route that looks like it came
/// from an ordinary AS [`CONFEDERATION_ID`], with no trace of the private
/// Member-AS numbers ([`CONFEDERATION_PATHVECTORD_MEMBER_AS`] or
/// [`CONFEDERATION_FRR_MEMBER_AS`]) on either side of the confederation
/// boundary.
#[tokio::test]
async fn route_from_confed_member_relayed_to_external_strips_confed_segments() {
    let h = ConfederationHarness::new().await;

    wait_for_gobgp_rib_entry(
        &h.external_id,
        CONFEDERATION_FRR_ROUTE,
        Duration::from_secs(20),
    )
    .await
    .expect("FRR's originated route did not reach the external GoBGP peer within 20 s");

    let rib = gobgp_rib_text(&h.external_id);
    assert!(
        rib.contains(&CONFEDERATION_ID.to_string()),
        "external peer's view of {CONFEDERATION_FRR_ROUTE} must show the confederation \
         identifier {CONFEDERATION_ID} in AS_PATH; got:\n{rib}"
    );
    assert!(
        !rib.contains(&CONFEDERATION_PATHVECTORD_MEMBER_AS.to_string()),
        "external peer must never see pathvectord's private Member-AS Number \
         {CONFEDERATION_PATHVECTORD_MEMBER_AS} — confederation segments must be stripped, \
         not merely relabeled; got:\n{rib}"
    );
    assert!(
        !rib.contains(&CONFEDERATION_FRR_MEMBER_AS.to_string()),
        "external peer must never see FRR's private Member-AS Number \
         {CONFEDERATION_FRR_MEMBER_AS} — confederation segments must be fully stripped \
         before export, not just have the local Member-AS prepended in front of them; \
         got:\n{rib}"
    );
}

/// RFC 5065 §4.1(b): a route originated by the genuinely external GoBGP
/// peer and relayed by pathvectord to the fellow Member-AS (FRR) must have
/// pathvectord's own Member-AS Number prepended as a new
/// `AS_CONFED_SEQUENCE` segment — FRR (confederation-aware) must see the
/// confederation segment distinctly from the external AS_SEQUENCE, not a
/// route that looks like an ordinary (non-confederation) eBGP announcement.
#[tokio::test]
async fn route_from_external_relayed_to_confed_member_prepends_confed_sequence() {
    let h = ConfederationHarness::new().await;

    wait_for_frr_rib_entry(
        &h.frr_id,
        CONFEDERATION_EXTERNAL_ROUTE,
        Duration::from_secs(20),
    )
    .await
    .expect("external peer's originated route did not reach FRR within 20 s");

    let route = frr_show_route_text(&h.frr_id, CONFEDERATION_EXTERNAL_ROUTE);
    // FRR's convention (matching RFC 5065's own recommended display style)
    // is to render AS_CONFED_SEQUENCE members in parentheses, distinct from
    // plain AS_SEQUENCE members. Check both the parenthesized Member-AS and
    // the plain external AS are present, in that relative order (confed
    // segment first, per RFC 5065 §4.1(b)'s "prepends a new path segment").
    let member_as_pos = route.find(&format!("({CONFEDERATION_PATHVECTORD_MEMBER_AS})"));
    let external_as_pos = route.find(&CONFEDERATION_EXTERNAL_AS.to_string());
    assert!(
        member_as_pos.is_some(),
        "FRR's view of {CONFEDERATION_EXTERNAL_ROUTE} must show pathvectord's Member-AS \
         Number {CONFEDERATION_PATHVECTORD_MEMBER_AS} as a confederation segment \
         (FRR renders these in parentheses); got:\n{route}"
    );
    assert!(
        external_as_pos.is_some(),
        "FRR's view of {CONFEDERATION_EXTERNAL_ROUTE} must still show the originating \
         external AS {CONFEDERATION_EXTERNAL_AS}; got:\n{route}"
    );
    assert!(
        member_as_pos < external_as_pos,
        "the confederation segment (Member-AS {CONFEDERATION_PATHVECTORD_MEMBER_AS}) must \
         be prepended ahead of the external AS_SEQUENCE, per RFC 5065 §4.1(b); got:\n{route}"
    );
    assert!(
        !route.contains(&CONFEDERATION_ID.to_string()),
        "FRR (a fellow Member-AS) must see pathvectord's private Member-AS Number, not \
         the public confederation identifier {CONFEDERATION_ID} — that substitution is \
         only for genuinely external peers; got:\n{route}"
    );
    // RFC 5065 §5.1: NEXT_HOP is unchanged by default toward a ConfedMember
    // peer (pathvectord has no `next_hop_self` configured for the FRR peer)
    // — FRR must see the external peer's own address, not pathvectord's.
    assert!(
        route.contains(&h.external_ip.to_string()),
        "FRR must see the external peer's own NEXT_HOP ({}) unchanged — pathvectord has no \
         next_hop_self configured for this peer, so RFC 5065 §5.1's default (unchanged) \
         applies; got:\n{route}",
        h.external_ip
    );
}

/// RFC 5065 §4.1(b)/(c) cover announcements; this proves a withdrawal
/// crosses the confederation boundary the same way. The genuinely external
/// GoBGP peer withdraws [`CONFEDERATION_EXTERNAL_ROUTE`] after it has
/// already been relayed to FRR — the route must disappear from FRR's own
/// RIB, not just stop being re-advertised (a route stuck in FRR's RIB after
/// its source withdrew it would be a stale/leaked route, exactly the
/// failure mode withdrawal propagation exists to prevent).
#[tokio::test]
async fn withdrawal_from_external_peer_propagates_to_confed_member() {
    let h = ConfederationHarness::new().await;

    wait_for_frr_rib_entry(
        &h.frr_id,
        CONFEDERATION_EXTERNAL_ROUTE,
        Duration::from_secs(20),
    )
    .await
    .expect("external peer's originated route did not reach FRR within 20 s");

    h.external_withdraw();

    wait_for_frr_rib_withdrawn(
        &h.frr_id,
        CONFEDERATION_EXTERNAL_ROUTE,
        Duration::from_secs(20),
    )
    .await
    .expect(
        "RFC 5065 §4.1(b): a withdrawal from the genuinely external peer must propagate \
         across the confederation boundary and remove the route from FRR's (the fellow \
         Member-AS) own RIB, not just stop future re-advertisement",
    );
}

/// RFC 5065 §5.2: "the restriction against sending the LOCAL_PREF attribute
/// to peers in a neighboring autonomous system within the same
/// confederation is removed." FRR (the fellow Member-AS) is RFC-compliant
/// and includes LOCAL_PREF on every UPDATE it sends over this
/// confederation session — checked against pathvectord's own Loc-RIB (via
/// its gRPC client) rather than FRR's or GoBGP's CLI text, since LOCAL_PREF
/// is never re-advertised to any eBGP-style peer regardless (it wouldn't
/// show up on the wire past pathvectord either way) — the property under
/// test is specifically whether pathvectord *accepted* it on import, not
/// whether it re-exports it.
#[tokio::test]
async fn local_pref_survives_relay_from_confed_member() {
    let mut h = ConfederationHarness::new().await;

    wait_for_gobgp_rib_entry(
        &h.external_id,
        CONFEDERATION_FRR_ROUTE,
        Duration::from_secs(20),
    )
    .await
    .expect("FRR's originated route did not reach the external GoBGP peer within 20 s");

    let route = h
        .client
        .get_best_route(CONFEDERATION_FRR_ROUTE)
        .await
        .expect("get_best_route gRPC call succeeded")
        .expect("FRR's route must be present in pathvectord's own Loc-RIB");
    assert!(
        route.local_pref.is_some(),
        "RFC 5065 §5.2: LOCAL_PREF from a fellow ConfedMember peer must be accepted, not \
         ignored like the ordinary eBGP case; got: {route:?}"
    );
}

/// RFC 5065 §5.2: MED is not stripped when relaying to a fellow
/// `ConfedMember` peer, unlike the `External` case (RFC 4271 doesn't
/// mandate stripping MED, but pathvectord's own convention does for
/// `External` — see `outbound.rs`'s `strip_med` split). The external peer
/// announces a route carrying an explicit MED; it must reach FRR with that
/// exact value preserved.
#[tokio::test]
async fn med_is_preserved_when_relayed_to_confed_member() {
    const MED: u32 = 50;
    let h = ConfederationHarness::new().await;

    h.external_announce_with_med(MED);

    wait_for_frr_rib_entry(
        &h.frr_id,
        CONFEDERATION_EXTERNAL_MED_ROUTE,
        Duration::from_secs(20),
    )
    .await
    .expect("MED-carrying route did not reach FRR within 20 s");

    let route = frr_show_route_text(&h.frr_id, CONFEDERATION_EXTERNAL_MED_ROUTE);
    // A bare `contains(&MED.to_string())` is not sufficient: the external
    // peer's own AS number (65099) contains "50" as a substring, so a
    // naive check would false-positive even with MED stripped. FRR renders
    // the actual MED as "metric <N>" in this text view, so match on that.
    let expected = format!("metric {MED}");
    assert!(
        route.contains(&expected),
        "RFC 5065 §5.2: MED ({MED}) must survive relay to a fellow ConfedMember peer; \
         got:\n{route}"
    );
}

/// RFC 1997: `NO_EXPORT_SUBCONFED` "MUST NOT be advertised to external BGP
/// peers (this includes peers in other members autonomous systems inside a
/// BGP confederation)" — unlike plain `NO_EXPORT`, which only blocks
/// genuinely external peers. The external peer announces a route carrying
/// this community; it must never reach FRR (a fellow Member-AS) at all.
#[tokio::test]
async fn no_export_subconfed_suppresses_advertisement_to_confed_member() {
    let h = ConfederationHarness::new().await;

    h.external_announce_no_export_subconfed();

    // Give pathvectord a real window to have processed and (if the
    // suppression check were broken) advertised the route before asserting
    // its absence — mirrors the negative-check pattern used for the
    // confederation-identifier loop test.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let route = frr_show_route_text(&h.frr_id, CONFEDERATION_EXTERNAL_NO_EXPORT_SUBCONFED_ROUTE);
    assert!(
        !route.contains(CONFEDERATION_EXTERNAL_NO_EXPORT_SUBCONFED_ROUTE),
        "RFC 1997: a route carrying NO_EXPORT_SUBCONFED must never reach a fellow \
         ConfedMember peer; got:\n{route}"
    );
}

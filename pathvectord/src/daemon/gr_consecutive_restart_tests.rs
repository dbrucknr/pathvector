// daemon/gr_consecutive_restart_tests.rs — issue #181: what a second session
// loss before End-of-RIB does with routes that are still stale.
//
// RFC 4724 §4.2, as replaced by RFC 8538 §4.1: "When the Receiving Speaker
// detects termination of the TCP session for a BGP session with a peer that has
// advertised the Graceful Restart Capability, it MUST retain the routes
// received from the peer for all the address families that were previously
// received in the Graceful Restart Capability and MUST mark them as stale
// routing information. [...] If the "N" bit has not been exchanged with the
// peer, then to deal with possible consecutive restarts, a route (from the
// peer) previously marked as stale MUST be deleted."
//
// RFC 8538 §2: new Graceful Restart parameters "apply once the session has
// transitioned into ESTABLISHED state", so the session being lost decides
// whether the "N" bit was exchanged.
//
// Each scenario: peer A announces a route it will refresh and one it will not,
// in both families, plus an authorized BLACKHOLE request (RFC 7999) it will
// not refresh. A's session is lost, comes back, refreshes only the first route
// and is lost again before any End-of-RIB.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use pathvector_rib::{BestPathChange, Staleness};
use pathvector_session::message::{
    Capability, GracefulRestartFamily, PathAttribute, Prefix, UpdateMessage,
};
use pathvector_session::transport::TerminationReason;
use pathvector_types::{AfiSafi, Community, Nlri, PeerType};

use super::issue_81_82_tests::support::{
    a, bh4, bh6, drop_a, eor_v4, eor_v6, established_gr, p4, p6, v4_update, v6_update,
};
use super::last_feasible_tests::{AS_A, LOCAL_AS, PEER_A, PEER_B, Receivers, sent_to};
use super::{DaemonState, build_local_capabilities};
use crate::blackhole::BlackholeScope;
use crate::daemon::tests::RecordingFib;

const KEPT_V4: &str = "10.0.0.0/8";
const KEPT_V6: &str = "2001:db8:1::/48";
const LOST_V4: &str = "172.16.0.0/12";
const LOST_V6: &str = "2001:db8:2::/48";
const HOLE_V4: &str = "192.0.2.77/32";
const HOLE_V6: &str = "2001:db8:ffff::77/128";

/// RFC 8538 §2: the "N" bit in the Restart Flags.
const N_BIT: u8 = 0x04;

/// Establishes A with a Graceful Restart capability for both families.
fn establish_a(state: &mut DaemonState, n_bit: bool) {
    let caps = [
        Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
        Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
        Capability::GracefulRestart {
            restart_flags: if n_bit { N_BIT } else { 0 },
            restart_time: 120,
            families: [AfiSafi::IPV4_UNICAST, AfiSafi::IPV6_UNICAST]
                .into_iter()
                .map(|afi_safi| GracefulRestartFamily {
                    afi_safi,
                    forwarding_preserved: true,
                })
                .collect(),
        },
    ];
    state.on_established(a(), PEER_A, PeerType::External, AS_A, 90, &caps, None);
}

/// A, B and C established, this speaker advertising the "N" bit, and A's three
/// routes per family announced. `n_bit` is whether A advertises it too.
fn announced(n_bit: bool) -> (DaemonState, Receivers, Arc<RecordingFib>) {
    let (mut state, receivers, fib) = established_gr();
    state.config_capabilities = build_local_capabilities(LOCAL_AS, 120, false, None);
    state.on_terminated(a(), TerminationReason::OperatorStop, false);
    establish_a(&mut state, n_bit);
    let scope = BlackholeScope::new(["192.0.2.0/24", "2001:db8:ffff::/48"]).unwrap();
    state.set_blackhole_scope(a(), Some(&scope));

    for prefix in [KEPT_V4, LOST_V4] {
        state.on_route_update(a(), v4_update(prefix, &[]));
    }
    for prefix in [KEPT_V6, LOST_V6] {
        state.on_route_update(a(), v6_update(prefix, &[]));
    }
    state.on_route_update(a(), v4_update(HOLE_V4, &[Community::BLACKHOLE]));
    state.on_route_update(a(), v6_update(HOLE_V6, &[Community::BLACKHOLE]));
    assert_eq!(bh4(&fib), vec![(p4(HOLE_V4), true)], "precondition");
    assert_eq!(bh6(&fib), vec![(p6(HOLE_V6), true)], "precondition");
    (state, receivers, fib)
}

fn refresh_kept(state: &mut DaemonState) {
    state.on_route_update(a(), v4_update(KEPT_V4, &[]));
    state.on_route_update(a(), v6_update(KEPT_V6, &[]));
}

/// Lose A, bring it back, refresh the kept routes only.
fn restart_once_without_eor(state: &mut DaemonState, n_bit: bool) {
    drop_a(state);
    establish_a(state, n_bit);
    refresh_kept(state);
}

fn adj_v4(state: &DaemonState, prefix: &str) -> Option<Staleness> {
    state.adj_ribs_in[&a()]
        .get(&p4(prefix))
        .map(|r| r.staleness)
}

fn adj_v6(state: &DaemonState, prefix: &str) -> Option<Staleness> {
    state.adj_ribs_in_v6[&a()]
        .get(&p6(prefix))
        .map(|r| r.staleness)
}

fn fib_withdrew_v4(fib: &RecordingFib, prefix: Nlri<Ipv4Addr>) -> bool {
    fib.v4
        .lock()
        .unwrap()
        .iter()
        .any(|c| matches!(c, BestPathChange::Withdrawn(n) if *n == prefix))
}

fn fib_withdrew_v6(fib: &RecordingFib, prefix: Nlri<Ipv6Addr>) -> bool {
    fib.v6
        .lock()
        .unwrap()
        .iter()
        .any(|c| matches!(c, BestPathChange::Withdrawn(n) if *n == prefix))
}

fn withdraws_v4(msgs: &[UpdateMessage], prefix: &str) -> bool {
    msgs.iter().any(|m| m.withdrawn.contains(&p4(prefix)))
}

fn withdraws_v6(msgs: &[UpdateMessage], prefix: &str) -> bool {
    let prefix = Prefix::V6(p6(prefix));
    msgs.iter()
        .flat_map(|m| &m.attributes)
        .any(|a| matches!(a, PathAttribute::MpUnreachNlri(u) if u.prefixes.contains(&prefix)))
}

/// What must be true once the still-stale routes are deleted: gone from the
/// Adj-RIB-In, Loc-RIB, FIB, blackhole book and the other peers, while the
/// refreshed routes are retained and marked stale.
fn assert_still_stale_deleted(
    state: &mut DaemonState,
    receivers: &mut Receivers,
    fib: &RecordingFib,
) {
    assert_eq!(adj_v4(state, LOST_V4), None, "IPv4 Adj-RIB-In");
    assert_eq!(adj_v6(state, LOST_V6), None, "IPv6 Adj-RIB-In");
    assert_eq!(adj_v4(state, HOLE_V4), None, "IPv4 blackhole request");
    assert_eq!(adj_v6(state, HOLE_V6), None, "IPv6 blackhole request");
    assert!(state.rib.loc_rib.best(&p4(LOST_V4)).is_none(), "Loc-RIB v4");
    assert!(
        state.rib.loc_rib_v6.best(&p6(LOST_V6)).is_none(),
        "Loc-RIB v6"
    );
    assert!(fib_withdrew_v4(fib, p4(LOST_V4)), "FIB v4");
    assert!(fib_withdrew_v6(fib, p6(LOST_V6)), "FIB v6");
    assert_eq!(
        bh4(fib).last(),
        Some(&(p4(HOLE_V4), false)),
        "null route v4"
    );
    assert_eq!(
        bh6(fib).last(),
        Some(&(p6(HOLE_V6), false)),
        "null route v6"
    );

    let to_b = sent_to(state, receivers, PEER_B);
    assert!(withdraws_v4(&to_b, LOST_V4), "peers v4: {to_b:?}");
    assert!(withdraws_v6(&to_b, LOST_V6), "peers v6: {to_b:?}");
    assert!(!withdraws_v4(&to_b, KEPT_V4), "refreshed v4 withdrawn");
    assert!(!withdraws_v6(&to_b, KEPT_V6), "refreshed v6 withdrawn");

    assert_eq!(adj_v4(state, KEPT_V4), Some(Staleness::GrStale));
    assert_eq!(adj_v6(state, KEPT_V6), Some(Staleness::GrStale));
    assert!(state.rib.loc_rib.best(&p4(KEPT_V4)).is_some());
    assert!(state.rib.loc_rib_v6.best(&p6(KEPT_V6)).is_some());
    assert!(state.gr.deadlines.contains_key(&a()));
}

/// Without the "N" bit: "a route (from the peer) previously marked as stale
/// MUST be deleted".
#[test]
fn second_loss_without_n_bit_deletes_still_stale_routes() {
    let (mut state, mut receivers, fib) = announced(false);
    restart_once_without_eor(&mut state, false);
    sent_to(&mut state, &mut receivers, PEER_B);

    drop_a(&mut state);

    assert_still_stale_deleted(&mut state, &mut receivers, &fib);
}

/// With the "N" bit exchanged the deletion rule does not apply (RFC 8538
/// §4.1): everything is retained and marked stale again.
#[test]
fn second_loss_with_n_bit_retains_still_stale_routes() {
    let (mut state, mut receivers, fib) = announced(true);
    restart_once_without_eor(&mut state, true);
    sent_to(&mut state, &mut receivers, PEER_B);

    drop_a(&mut state);

    for prefix in [KEPT_V4, LOST_V4, HOLE_V4] {
        assert_eq!(adj_v4(&state, prefix), Some(Staleness::GrStale), "{prefix}");
    }
    for prefix in [KEPT_V6, LOST_V6, HOLE_V6] {
        assert_eq!(adj_v6(&state, prefix), Some(Staleness::GrStale), "{prefix}");
    }
    assert!(state.rib.loc_rib.best(&p4(LOST_V4)).is_some());
    assert!(state.rib.loc_rib_v6.best(&p6(LOST_V6)).is_some());
    assert_eq!(bh4(&fib), vec![(p4(HOLE_V4), true)]);
    assert_eq!(bh6(&fib), vec![(p6(HOLE_V6), true)]);
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(!withdraws_v4(&to_b, LOST_V4), "{to_b:?}");
    assert!(!withdraws_v6(&to_b, LOST_V6), "{to_b:?}");
}

/// The first loss deletes nothing: no route was "previously marked as stale".
#[test]
fn first_loss_without_n_bit_retains_every_route() {
    let (mut state, _receivers, fib) = announced(false);

    drop_a(&mut state);

    for prefix in [KEPT_V4, LOST_V4, HOLE_V4] {
        assert_eq!(adj_v4(&state, prefix), Some(Staleness::GrStale), "{prefix}");
    }
    for prefix in [KEPT_V6, LOST_V6, HOLE_V6] {
        assert_eq!(adj_v6(&state, prefix), Some(Staleness::GrStale), "{prefix}");
    }
    assert_eq!(bh4(&fib), vec![(p4(HOLE_V4), true)]);
    assert_eq!(bh6(&fib), vec![(p6(HOLE_V6), true)]);
}

/// The session now being lost did not exchange the "N" bit, although the one
/// before it did, so the deletion rule applies.
#[test]
fn second_loss_follows_the_n_bit_of_the_session_being_lost() {
    let (mut state, mut receivers, fib) = announced(true);
    drop_a(&mut state);
    establish_a(&mut state, false);
    refresh_kept(&mut state);
    sent_to(&mut state, &mut receivers, PEER_B);

    drop_a(&mut state);

    assert_still_stale_deleted(&mut state, &mut receivers, &fib);
}

/// An End-of-RIB for one family settles that family only: the other family's
/// still-stale routes are deleted by the next loss.
#[test]
fn second_loss_after_one_family_end_of_rib_deletes_the_other_familys_stale_routes() {
    let (mut state, mut receivers, _fib) = announced(false);
    restart_once_without_eor(&mut state, false);
    state.on_route_update(a(), eor_v4());
    sent_to(&mut state, &mut receivers, PEER_B);

    drop_a(&mut state);

    assert_eq!(adj_v6(&state, LOST_V6), None);
    assert_eq!(adj_v4(&state, KEPT_V4), Some(Staleness::GrStale));
    assert_eq!(adj_v6(&state, KEPT_V6), Some(Staleness::GrStale));
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(withdraws_v6(&to_b, LOST_V6), "{to_b:?}");
}

/// The next session's End-of-RIB still removes what that session did not
/// refresh: here nothing it kept, so the deletion leaves no bookkeeping behind.
#[test]
fn resynchronisation_after_a_second_loss_keeps_what_it_refreshes() {
    let (mut state, _receivers, _fib) = announced(false);
    restart_once_without_eor(&mut state, false);
    drop_a(&mut state);

    establish_a(&mut state, false);
    refresh_kept(&mut state);
    state.on_route_update(a(), eor_v4());
    state.on_route_update(a(), eor_v6());

    assert_eq!(adj_v4(&state, KEPT_V4), Some(Staleness::Fresh));
    assert_eq!(adj_v6(&state, KEPT_V6), Some(Staleness::Fresh));
    assert!(state.gr.stale_nlri.is_empty());
    assert!(state.gr.stale_nlri_v6.is_empty());
}

/// A loss during resynchronisation drops that session's End-of-RIB
/// bookkeeping: it describes a resynchronisation that is over.
#[test]
fn a_second_loss_discards_the_interrupted_end_of_rib_bookkeeping() {
    for n_bit in [false, true] {
        let (mut state, _receivers, _fib) = announced(n_bit);
        restart_once_without_eor(&mut state, n_bit);

        drop_a(&mut state);

        assert!(state.gr.stale_nlri.is_empty(), "N={n_bit}");
        assert!(state.gr.stale_nlri_v6.is_empty(), "N={n_bit}");
    }
}

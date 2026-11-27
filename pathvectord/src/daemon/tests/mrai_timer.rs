//! Unit tests of [`MraiTracker`]'s bookkeeping. End-to-end behaviour
//! (what reaches the peer) is in `daemon/mrai_flush_tests.rs`.
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use crate::daemon::*;

const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

fn nlri(s: &str) -> Nlri<Ipv4Addr> {
    s.parse().unwrap()
}

fn make_state() -> DaemonState {
    DaemonState::new(
        65001,
        Ipv4Addr::new(1, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &[],
        HashMap::new(),
        vec![],
    )
}

fn ago(d: Duration) -> Instant {
    Instant::now().checked_sub(d).expect("clock far from epoch")
}

#[test]
fn destination_sent_just_now_is_not_ready() {
    let mut t = MraiTracker::<Ipv4Addr>::new();
    let n = nlri("10.0.0.0/24");
    t.set_last_sent(PEER, n, Instant::now());
    t.defer(PEER, n);
    assert!(t.take_ready(Instant::now()).is_empty());
    assert!(t.has_pending(), "still held back inside the interval");
}

#[test]
fn destination_is_ready_once_interval_elapsed() {
    let mut t = MraiTracker::<Ipv4Addr>::new();
    let n = nlri("10.0.0.0/24");
    t.set_last_sent(PEER, n, ago(MRAI + Duration::from_secs(1)));
    t.defer(PEER, n);
    assert_eq!(t.take_ready(Instant::now()), vec![n]);
    assert!(!t.has_pending());
}

/// §9.2.1.1 is per destination: a recently-sent destination stays held
/// back even when another destination for the same peer is released.
#[test]
fn take_ready_releases_only_elapsed_destinations() {
    let mut t = MraiTracker::<Ipv4Addr>::new();
    let old = nlri("10.0.0.0/24");
    let fresh = nlri("10.0.1.0/24");
    t.set_last_sent(PEER, old, ago(MRAI + Duration::from_secs(1)));
    t.set_last_sent(PEER, fresh, Instant::now());
    t.defer(PEER, old);
    t.defer(PEER, fresh);
    assert_eq!(t.take_ready(Instant::now()), vec![old]);
    assert!(t.has_pending(), "the fresh destination is still held back");
    assert!(t.take_ready(Instant::now()).is_empty());
}

#[test]
fn remove_peer_drops_pending() {
    let mut t = MraiTracker::<Ipv4Addr>::new();
    t.defer(PEER, nlri("10.0.0.0/24"));
    t.remove_peer(PEER);
    assert!(!t.has_pending());
}

#[test]
fn has_mrai_pending_false_when_empty() {
    let state = make_state();
    assert!(!state.has_mrai_pending());
}

#[test]
fn has_mrai_pending_covers_both_families() {
    let mut state = make_state();
    state.mrai.defer(PEER, nlri("10.0.0.0/24"));
    assert!(state.has_mrai_pending());

    let mut state = make_state();
    state.mrai_v6.defer(PEER, "2001:db8::/32".parse().unwrap());
    assert!(state.has_mrai_pending());
}

#[test]
fn flush_mrai_pending_clears_elapsed_pending() {
    let mut state = make_state();
    let n = nlri("10.0.0.0/24");
    state.mrai.defer(PEER, n);
    state
        .mrai
        .set_last_sent(PEER, n, ago(MRAI + Duration::from_secs(1)));

    // No peers are configured, so the re-propagation is a no-op, but the
    // pending set must be drained.
    state.flush_mrai_pending();

    assert!(!state.has_mrai_pending(), "pending cleared after flush");
}

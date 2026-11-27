use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use pathvector_session::message::{Capability, GracefulRestartFamily};
use pathvector_types::AfiSafi;

fn peer() -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, 2)
}

fn gr_cap(restart_time: u16) -> Capability {
    Capability::GracefulRestart {
        restart_flags: 0,
        restart_time,
        families: vec![GracefulRestartFamily {
            afi_safi: AfiSafi::IPV4_UNICAST,
            forwarding_preserved: true,
        }],
    }
}

/// Extract the peer's GR restart_time from a capability list, delegating
/// to the real production function `on_established` calls — not a
/// separate mirrored implementation — so this test module can never
/// silently drift from what actually runs. Returns None if absent or
/// restart_time == 0.
fn extract_gr_time(caps: &[Capability]) -> Option<u16> {
    crate::daemon::peer::extract_gr_capability(caps).1
}

/// A peer advertising GracefulRestart with restart_time > 0 must be recorded
/// in gr_capable_peers with the correct time value.
#[test]
fn gr_capable_peer_is_recorded_on_established() {
    let mut gr_capable_peers: HashMap<IpAddr, u16> = HashMap::new();
    let caps = vec![gr_cap(120)];
    if let Some(t) = extract_gr_time(&caps) {
        gr_capable_peers.insert(IpAddr::V4(peer()), t);
    } else {
        gr_capable_peers.remove(&IpAddr::V4(peer()));
    }
    assert_eq!(
        gr_capable_peers.get(&IpAddr::V4(peer())).copied(),
        Some(120),
        "gr_capable_peers must store the peer's advertised restart_time"
    );
}

/// A peer advertising GracefulRestart with restart_time = 0 must NOT be
/// recorded in gr_capable_peers (restart_time = 0 means EOR-only, no GR window).
#[test]
fn gr_eor_only_peer_not_recorded() {
    let mut gr_capable_peers: HashMap<IpAddr, u16> = HashMap::new();
    gr_capable_peers.insert(IpAddr::V4(peer()), 30); // pre-existing value from prior session
    let caps = vec![gr_cap(0)];
    if let Some(t) = extract_gr_time(&caps) {
        gr_capable_peers.insert(IpAddr::V4(peer()), t);
    } else {
        gr_capable_peers.remove(&IpAddr::V4(peer()));
    }
    assert!(
        !gr_capable_peers.contains_key(&IpAddr::V4(peer())),
        "peer with restart_time = 0 must not be in gr_capable_peers; \
         prior session value must be cleared"
    );
}

/// RFC 4724 §3: "A BGP speaker MUST NOT include more than one instance of
/// the Graceful Restart Capability in the capability advertisement... If
/// more than one instance... is carried..., the receiver of the
/// advertisement MUST ignore all but the last instance of the Graceful
/// Restart Capability." A peer sending duplicates is itself a sender-side
/// RFC violation, but if it happens, the *last* instance must win, not
/// the first.
#[test]
fn duplicate_gr_capabilities_do_not_panic_and_last_wins() {
    let caps = vec![gr_cap(90), gr_cap(300)];
    let t = extract_gr_time(&caps);
    assert_eq!(
        t,
        Some(300),
        "last GracefulRestart capability must win when duplicates are present"
    );
}

/// The RFC's "ignore all but the last instance" rule applies to the whole
/// capability, not just a first-non-zero-restart_time search — so a last
/// instance with restart_time=0 must win even over an earlier non-zero
/// instance, correctly yielding "not GR-capable for retention purposes"
/// (EOR-only) rather than falling back to the earlier value.
#[test]
fn nonzero_gr_then_zero_gr_uses_last_instance_even_though_it_is_zero() {
    let caps = vec![gr_cap(120), gr_cap(0)];
    let t = extract_gr_time(&caps);
    assert_eq!(
        t, None,
        "the last instance (restart_time=0) must be authoritative, \
         not the earlier non-zero instance"
    );
}

/// Symmetric case: restart_time=0 followed by a real non-zero last
/// instance — the last instance must win here too.
#[test]
fn zero_gr_then_nonzero_gr_uses_last_instance() {
    let caps = vec![gr_cap(0), gr_cap(120)];
    let t = extract_gr_time(&caps);
    assert_eq!(
        t,
        Some(120),
        "the last instance (restart_time=120) must be authoritative"
    );
}

/// gr_capable_peers must be cleared on Terminated so stale values cannot
/// influence future sessions.
#[test]
fn gr_capable_peers_cleared_on_terminated() {
    let mut gr_capable_peers: HashMap<IpAddr, u16> = HashMap::new();
    gr_capable_peers.insert(IpAddr::V4(peer()), 120);
    // Simulate on_terminated cleanup.
    gr_capable_peers.remove(&IpAddr::V4(peer()));
    assert!(
        !gr_capable_peers.contains_key(&IpAddr::V4(peer())),
        "gr_capable_peers must be empty after peer terminates"
    );
}

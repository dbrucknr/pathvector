//! ── RFC 4724 §2 End-of-RIB receive-side detection tests ──────────────────────

use std::net::{IpAddr, Ipv4Addr};

use pathvector_session::message::{MpUnreachNlri, PathAttribute, UpdateMessage};
use pathvector_session::transport::TerminationReason;

use pathvector_types::{AfiSafi, PeerType};

use crate::daemon::tests::make_state;

const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const PEER_AS: u32 = 65002;
const LOCAL_AS: u32 = 65001;

fn establish_peer(state: &mut super::DaemonState) {
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &[],
        None,
    );
}

fn ipv4_eor() -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![],
        announced: vec![],
    }
}

fn ipv6_eor() -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi_safi: AfiSafi::IPV6_UNICAST,
            prefixes: vec![],
        })],
        announced: vec![],
    }
}

// Test 1: IPv4 EOR is detected and state is recorded.
#[test]
fn test_ipv4_eor_received_is_recorded() {
    let (mut state, _rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
    establish_peer(&mut state);

    let result = state.on_route_update(IpAddr::V4(PEER_IP), ipv4_eor());
    assert!(result.is_none(), "EOR must not return a NOTIFICATION");
    assert!(
        state.rib.eor_received.contains(&IpAddr::V4(PEER_IP)),
        "eor_received must contain peer after IPv4 EOR"
    );
}

// Test 2: IPv6 EOR is detected and state is recorded.
#[test]
fn test_ipv6_eor_received_is_recorded() {
    let (mut state, _rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
    establish_peer(&mut state);

    let result = state.on_route_update(IpAddr::V4(PEER_IP), ipv6_eor());
    assert!(result.is_none(), "EOR must not return a NOTIFICATION");
    assert!(
        state.rib.eor_received_v6.contains(&IpAddr::V4(PEER_IP)),
        "eor_received_v6 must contain peer after IPv6 EOR"
    );
}

// Test 3: IPv4 EOR must return early and not insert into Adj-RIB-In.
#[test]
fn test_ipv4_eor_does_not_insert_route() {
    let (mut state, _rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
    establish_peer(&mut state);

    state.on_route_update(IpAddr::V4(PEER_IP), ipv4_eor());

    let ari_len = state
        .adj_ribs_in
        .get(&IpAddr::V4(PEER_IP))
        .map_or(0, pathvector_rib::AdjRibIn::len);
    assert_eq!(ari_len, 0, "EOR must not insert a route into Adj-RIB-In");
}

// Test 4: EOR state is cleared when the session terminates.
#[test]
fn test_eor_state_cleared_on_termination() {
    let (mut state, _rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
    establish_peer(&mut state);
    state.on_route_update(IpAddr::V4(PEER_IP), ipv4_eor());
    assert!(state.rib.eor_received.contains(&IpAddr::V4(PEER_IP)));

    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, false);

    assert!(
        !state.rib.eor_received.contains(&IpAddr::V4(PEER_IP)),
        "eor_received must be cleared after session termination"
    );
}

// Test 5: An UPDATE with attributes (but no NLRIs) is not an EOR.
#[test]
fn test_update_with_attributes_is_not_eor() {
    use pathvector_types::{AsPath, Origin};
    let (mut state, _rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
    establish_peer(&mut state);

    // Build an UPDATE that has attributes but no NLRI — NOT an IPv4 EOR.
    let msg = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::new()),
            PathAttribute::NextHop("10.0.0.2".parse().unwrap()),
        ],
        announced: vec![],
    };
    state.on_route_update(IpAddr::V4(PEER_IP), msg);

    assert!(
        !state.rib.eor_received.contains(&IpAddr::V4(PEER_IP)),
        "UPDATE with attributes must not be recorded as IPv4 EOR"
    );
}

// Test 6: Stale EOR state from a previous session is cleared on re-establish.
#[test]
fn test_eor_state_cleared_on_re_establish() {
    let (mut state, _rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
    establish_peer(&mut state);
    state.on_route_update(IpAddr::V4(PEER_IP), ipv4_eor());
    assert!(state.rib.eor_received.contains(&IpAddr::V4(PEER_IP)));

    // Simulate reconnect without explicit termination by calling on_established again.
    establish_peer(&mut state);

    assert!(
        !state.rib.eor_received.contains(&IpAddr::V4(PEER_IP)),
        "eor_received must be cleared on session re-establishment"
    );
}

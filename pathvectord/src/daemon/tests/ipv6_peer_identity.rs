//! ── IPv6-identified peer: route/policy/GR ────────────────────────────────────
//!
//! Every other IPv6-flavored test in this file (v6_tests, test_gr_phase2's own
//! IPv6 coverage, etc.) exercises IPv6 *NLRI* — a route whose prefix or
//! next-hop is an IPv6 address — carried by a peer whose own identity happens
//! to be an `Ipv4Addr`-shaped literal (just typed `IpAddr`, per the peer-
//! identity migration). None of them construct a peer whose identity is a
//! genuine `Ipv6Addr`. Since every peer-identity-keyed collection in
//! `DaemonState`/`RibSnapshot` is now `IpAddr`-keyed uniformly (no code path
//! pattern-matches on `IpAddr::V4` vs `V6` for peer identity), there's good
//! structural reason to expect this already works — these tests turn that
//! expectation into a verified fact for the three code paths a v6-transport
//! peer runs through as both an import source and an export destination: RIB
//! insertion + propagation, export-policy filtering, and RFC 4724 GR.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pathvector_session::message::{
    Capability, GracefulRestartFamily, PathAttribute, UpdateMessage,
};
use pathvector_session::transport::TerminationReason;
use pathvector_types::{AfiSafi, AsPath, Asn, Nlri, Origin, PeerType};

use crate::config;
use crate::daemon::*;

fn nlri(s: &str) -> Nlri<Ipv4Addr> {
    s.parse().unwrap()
}

fn drain_all(receivers: &mut HashMap<IpAddr, mpsc::Receiver<UpdateMessage>>) {
    for rx in receivers.values_mut() {
        while rx.try_recv().is_ok() {}
    }
}

fn make_state(
    local_as: u32,
    peers: &[(IpAddr, u32)],
) -> (DaemonState, HashMap<IpAddr, mpsc::Receiver<UpdateMessage>>) {
    let mut senders = HashMap::new();
    let mut receivers = HashMap::new();
    for &(addr, _) in peers {
        let (tx, rx) = mpsc::channel(64);
        senders.insert(addr, tx);
        receivers.insert(addr, rx);
    }
    let peer_configs: Vec<config::PeerConfig> = peers
        .iter()
        .map(|&(address, remote_as)| config::PeerConfig {
            address,
            port: 179,
            remote_as,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
            confederation_member: false,
            blackhole_authorized_prefixes: None,
        })
        .collect();
    let state = DaemonState::new(
        local_as,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &peer_configs,
        senders,
        vec![],
    );
    (state, receivers)
}

fn announce(prefix: &str, origin_as: u32) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(origin_as)])),
            PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
        ],
        announced: vec![nlri(prefix)],
    }
}

/// A peer identified by a genuine `Ipv6Addr` (not an `Ipv4Addr` literal
/// wearing an `IpAddr` type) announces a route; it must be accepted into
/// LocRib and propagated to a second, v4-identified peer exactly as if
/// the source peer's transport were IPv4. Peer *transport* family and
/// NLRI family are independent — this proves the daemon doesn't
/// accidentally conflate them for the source side.
#[test]
fn route_from_ipv6_identified_peer_is_accepted_and_propagated() {
    let peer_v6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
    let peer_v4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let (mut state, mut receivers) = make_state(65001, &[(peer_v6, 65002), (peer_v4, 65003)]);

    state.on_established(
        peer_v6,
        Ipv4Addr::new(10, 0, 0, 2), // BGP Identifier is always 4 bytes (RFC 6286)
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.on_established(
        peer_v4,
        Ipv4Addr::new(10, 0, 0, 3),
        PeerType::External,
        65003,
        90,
        &[],
        None,
    );
    drain_all(&mut receivers);

    state.on_route_update(peer_v6, announce("192.0.2.0/24", 65002));
    state.flush_pending();

    assert_eq!(
        state.rib.loc_rib.len(),
        1,
        "route from the IPv6-identified peer must land in LocRib"
    );

    let msg = receivers
        .get_mut(&peer_v4)
        .unwrap()
        .try_recv()
        .expect("v4-identified peer should receive the propagated UPDATE");
    assert_eq!(msg.announced, vec![nlri("192.0.2.0/24")]);
}

/// `export_default = "reject"` on an IPv6-identified peer must actually
/// block propagation to it, exactly as it would for a v4-identified
/// peer — proving export-policy enforcement doesn't silently bypass
/// itself for a v6 destination.
#[test]
fn export_reject_blocks_propagation_to_ipv6_identified_peer() {
    let peer_v4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let peer_v6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3));

    let peer_configs = vec![
        config::PeerConfig {
            address: peer_v4,
            port: 179,
            remote_as: 65002,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
            confederation_member: false,
            blackhole_authorized_prefixes: None,
        },
        config::PeerConfig {
            address: peer_v6,
            port: 179,
            remote_as: 65003,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Reject),
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
            confederation_member: false,
            blackhole_authorized_prefixes: None,
        },
    ];
    let mut senders = HashMap::new();
    let mut receivers = HashMap::new();
    for &addr in &[peer_v4, peer_v6] {
        let (tx, rx) = mpsc::channel(64);
        senders.insert(addr, tx);
        receivers.insert(addr, rx);
    }
    let mut state = DaemonState::new(
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &peer_configs,
        senders,
        vec![],
    );

    state.on_established(
        peer_v4,
        Ipv4Addr::new(10, 0, 0, 2),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.on_established(
        peer_v6,
        Ipv4Addr::new(10, 0, 0, 3),
        PeerType::External,
        65003,
        90,
        &[],
        None,
    );
    drain_all(&mut receivers);

    state.on_route_update(peer_v4, announce("198.51.100.0/24", 65002));
    state.flush_pending();

    assert!(
        receivers.get_mut(&peer_v6).unwrap().try_recv().is_err(),
        "export_default = reject must block propagation to the IPv6-identified peer"
    );
}

/// RFC 4724 §4.2 — an unclean termination from a GR-capable peer whose
/// identity is IPv6 must retain routes in AdjRibIn/LocRib exactly as it
/// would for a v4-identified peer.
#[test]
fn unclean_termination_of_ipv6_identified_gr_peer_retains_routes() {
    let peer_v6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
    let (mut state, _rxs) = make_state(65001, &[(peer_v6, 65002)]);

    let caps = vec![
        Capability::FourByteAsn(65002),
        Capability::GracefulRestart {
            restart_flags: 0,
            restart_time: 120,
            families: vec![GracefulRestartFamily {
                afi_safi: AfiSafi::IPV4_UNICAST,
                forwarding_preserved: false,
            }],
        },
    ];
    state.on_established(
        peer_v6,
        Ipv4Addr::new(10, 0, 0, 2),
        PeerType::External,
        65002,
        90,
        &caps,
        None,
    );
    state.on_route_update(peer_v6, announce("192.0.2.0/24", 65002));
    assert_eq!(
        state.rib.loc_rib.len(),
        1,
        "route must be in LocRib before termination"
    );

    state.on_terminated(peer_v6, TerminationReason::Unclean, true);

    assert!(
        state.adj_ribs_in[&peer_v6]
            .get(&nlri("192.0.2.0/24"))
            .is_some(),
        "AdjRibIn route must be retained during the GR window"
    );
    assert_eq!(
        state.rib.loc_rib.len(),
        1,
        "LocRib route must be retained during the GR window"
    );
    assert!(
        state.gr.deadlines.contains_key(&peer_v6),
        "gr_deadlines must be armed for the IPv6-identified peer"
    );
}

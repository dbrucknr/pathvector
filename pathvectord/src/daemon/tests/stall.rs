use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use pathvector_policy::DefaultAction;
use pathvector_types::{AsPath, Asn, NextHop, Nlri, Origin, PeerType};

use crate::config;
use crate::daemon::*;

// ── helpers ───────────────────────────────────────────────────────────────

fn nlri(s: &str) -> Nlri<Ipv4Addr> {
    s.parse().unwrap()
}

fn base_route(prefix: &str, nh: Ipv4Addr, pt: PeerType) -> pathvector_rib::Route<Ipv4Addr> {
    RouteBuilder::new(
        nlri(prefix),
        Origin::Igp,
        AsPath::from_sequence(vec![Asn::new(65002)]),
    )
    .next_hop(NextHop::V4(nh))
    .peer_type(pt)
    .build()
}

/// Build a `DaemonState` where every peer's outbound channel has `capacity`.
/// Returns the state and a map of receivers so the caller can drain channels.
fn make_capped(
    peers: &[(IpAddr, u32)],
    capacity: usize,
) -> (DaemonState, HashMap<IpAddr, mpsc::Receiver<UpdateMessage>>) {
    let mut senders = HashMap::new();
    let mut receivers = HashMap::new();
    for &(ip, _) in peers {
        let (tx, rx) = mpsc::channel(capacity);
        senders.insert(ip, tx);
        receivers.insert(ip, rx);
    }
    let peer_configs: Vec<config::PeerConfig> = peers
        .iter()
        .map(|&(address, remote_as)| config::PeerConfig {
            address,
            port: 179,
            import_default_v6: None,
            md5_password: None,
            remote_as,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
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
        65001,
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

/// Fill a channel with a dummy UPDATE so the next `try_send` fails.
fn fill_channel(state: &DaemonState, peer: IpAddr) {
    let tx = state.update_senders.get(&peer).unwrap();
    tx.try_send(UpdateMessage {
        withdrawn: vec![nlri("0.0.0.0/0")],
        attributes: vec![],
        announced: vec![],
    })
    .expect("channel must have room for the fill message");
}

// ── take_stalled_peers ────────────────────────────────────────────────────

#[test]
fn take_stalled_peers_returns_and_clears() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _) = make_capped(&[(peer_ip, 64)], 64);

    assert!(state.take_stalled_peers().is_empty(), "initially empty");
    state.stalled_peers.push(peer_ip);
    let stalled = state.take_stalled_peers();
    assert_eq!(stalled, vec![peer_ip]);
    assert!(state.take_stalled_peers().is_empty(), "cleared after take");
}

// ── on_established stalled path ───────────────────────────────────────────

#[test]
fn on_established_marks_stalled_when_channel_full() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _rx) = make_capped(&[(peer_ip, 1)], 1);

    // Pre-populate the Loc-RIB from a third-party peer so that on_established
    // has something to propagate.
    let src = PeerId::new(IpAddr::V4("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
    state.rib_insert_v4(
        src,
        base_route(
            "10.0.0.0/8",
            "10.0.0.9".parse().unwrap(),
            PeerType::External,
        ),
    );

    // Saturate the channel; propagate_prefix's try_send will fail.
    fill_channel(&state, peer_ip);

    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    assert!(
        !state.take_stalled_peers().is_empty(),
        "peer must be stalled when outbound channel is full during table dump"
    );
}

// ── on_terminated stalled path ────────────────────────────────────────────

#[test]
fn on_terminated_marks_stalled_when_channel_full() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    // Build with mixed capacities: peer_a gets a large channel, peer_b gets cap 1.
    let (tx_a, _rx_a) = mpsc::channel::<UpdateMessage>(64);
    let (tx_b, _rx_b) = mpsc::channel::<UpdateMessage>(1);
    let peer_configs = vec![
        config::PeerConfig {
            address: IpAddr::V4(peer_a),
            import_default_v6: None,
            md5_password: None,
            port: 179,
            remote_as: 65002,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
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
            import_default_v6: None,
            md5_password: None,
            address: IpAddr::V4(peer_b),
            port: 179,
            remote_as: 65003,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
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
    senders.insert(IpAddr::V4(peer_a), tx_a);
    senders.insert(IpAddr::V4(peer_b), tx_b.clone());
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
        IpAddr::V4(peer_a),
        peer_a,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(peer_b),
        peer_b,
        PeerType::External,
        65003,
        90,
        &[],
        None,
    );

    // Announce a route from peer_a → it ends up in Loc-RIB.
    state.on_route_update(
        IpAddr::V4(peer_a),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(peer_a),
            ],
            announced: vec![nlri("192.168.0.0/16")],
        },
    );

    // Flush pending decisions to fill peer_b's channel (capacity 1).
    // We do NOT drain peer_b's channel so the slot stays occupied.
    state.flush_pending();

    // Terminate peer_a: the withdraw for peer_b's channel will fail (full).
    state.on_terminated(IpAddr::V4(peer_a), TerminationReason::Unclean, true);
    assert!(
        !state.take_stalled_peers().is_empty(),
        "peer_b must be stalled when its channel is full during termination propagation"
    );
}

// ── set_import_default propagation loop ───────────────────────────────────

#[test]
fn set_import_default_propagates_to_established_peer() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut receivers) = make_capped(
        &[(IpAddr::V4(peer_a), 65002), (IpAddr::V4(peer_b), 65003)],
        64,
    );

    state.on_established(
        IpAddr::V4(peer_a),
        peer_a,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(peer_b),
        peer_b,
        PeerType::External,
        65003,
        90,
        &[],
        None,
    );

    // Announce a route from peer_a via on_route_update so that it is
    // properly recorded in Adj-RIB-In, Loc-RIB, AND peer_b's Adj-RIB-Out.
    state.on_route_update(
        IpAddr::V4(peer_a),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(peer_a),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );

    // Drain the UPDATE that on_route_update propagated so receivers are clear.
    state.flush_pending();
    receivers
        .get_mut(&IpAddr::V4(peer_b))
        .unwrap()
        .try_recv()
        .ok();
    receivers
        .get_mut(&IpAddr::V4(peer_a))
        .unwrap()
        .try_recv()
        .ok();

    // Flip the import policy to Reject — route evicted from Loc-RIB;
    // peer_b must receive a WITHDRAW.
    state.set_import_default(IpAddr::V4(peer_a), DefaultAction::Reject);
    state.flush_pending();

    receivers
        .get_mut(&IpAddr::V4(peer_b))
        .unwrap()
        .try_recv()
        .expect("peer_b must receive a WITHDRAW after set_import_default → Reject");
}

#[test]
fn set_import_default_marks_stalled_when_channel_full() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();

    // peer_a gets a large channel; peer_b gets capacity 1.
    let (tx_a, _rx_a) = mpsc::channel::<UpdateMessage>(64);
    let (tx_b, _rx_b) = mpsc::channel::<UpdateMessage>(1);
    let peer_configs = vec![
        config::PeerConfig {
            address: IpAddr::V4(peer_a),
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
            address: IpAddr::V4(peer_b),
            port: 179,
            remote_as: 65003,
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
    ];
    let mut senders = HashMap::new();
    senders.insert(IpAddr::V4(peer_a), tx_a);
    senders.insert(IpAddr::V4(peer_b), tx_b);
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
        IpAddr::V4(peer_a),
        peer_a,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(peer_b),
        peer_b,
        PeerType::External,
        65003,
        90,
        &[],
        None,
    );

    // Announce via on_route_update so adj_rib_out[peer_b] has the route.
    state.on_route_update(
        IpAddr::V4(peer_a),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(peer_a),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );
    // Flush pending to fill peer_b's channel (capacity 1). Do NOT drain it.
    state.flush_pending();

    // set_import_default tries to send WITHDRAW to peer_b but channel is full.
    state.set_import_default(IpAddr::V4(peer_a), DefaultAction::Reject);
    state.flush_pending();
    assert!(
        !state.take_stalled_peers().is_empty(),
        "peer_b must be stalled when channel is full during set_import_default propagation"
    );
}

// ── flush_pending coalescing ──────────────────────────────────────────────

/// Multiple `on_route_update` calls must be coalesced into fewer outbound
/// UPDATE messages when `flush_pending` is called once after both updates.
///
/// This validates RFC 4271 §9.2 "combine as many feasible routes as
/// possible": two separate route updates with the same attribute set must
/// arrive at the peer in a single UPDATE message, not two separate ones.
#[test]
fn flush_pending_coalesces_multi_update_burst() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut receivers) = make_capped(
        &[(IpAddr::V4(peer_a), 65002), (IpAddr::V4(peer_b), 65003)],
        64,
    );

    state.on_established(
        IpAddr::V4(peer_a),
        peer_a,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(peer_b),
        peer_b,
        PeerType::External,
        65003,
        90,
        &[],
        None,
    );
    while receivers
        .get_mut(&IpAddr::V4(peer_a))
        .unwrap()
        .try_recv()
        .is_ok()
    {}
    while receivers
        .get_mut(&IpAddr::V4(peer_b))
        .unwrap()
        .try_recv()
        .is_ok()
    {}

    // Two separate on_route_update calls — simulating two BGP UPDATEs
    // arriving back-to-back from peer_a, each with a different prefix but
    // identical path attributes. flush_pending must combine them.
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
        PathAttribute::NextHop(peer_a),
    ];
    state.on_route_update(
        IpAddr::V4(peer_a),
        UpdateMessage {
            withdrawn: vec![],
            attributes: attrs.clone(),
            announced: vec![nlri("10.0.0.0/8")],
        },
    );
    state.on_route_update(
        IpAddr::V4(peer_a),
        UpdateMessage {
            withdrawn: vec![],
            attributes: attrs,
            announced: vec![nlri("172.16.0.0/12")],
        },
    );

    // Flush once — both prefixes should be in a single UPDATE to peer_b.
    state.flush_pending();

    let msg = receivers
        .get_mut(&IpAddr::V4(peer_b))
        .unwrap()
        .try_recv()
        .expect("peer_b must receive a batched UPDATE");

    assert!(
        msg.announced.contains(&nlri("10.0.0.0/8")),
        "batched UPDATE must contain 10.0.0.0/8"
    );
    assert!(
        msg.announced.contains(&nlri("172.16.0.0/12")),
        "batched UPDATE must contain 172.16.0.0/12"
    );

    // Crucially: no second UPDATE message should be queued.
    assert!(
        receivers
            .get_mut(&IpAddr::V4(peer_b))
            .unwrap()
            .try_recv()
            .is_err(),
        "coalescing must produce a single UPDATE, not two separate ones"
    );
}

/// After peer termination, any buffered decisions for that peer must be
/// discarded — they must not be sent to the dead session.
#[test]
fn flush_pending_clears_on_terminated() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut receivers) = make_capped(
        &[(IpAddr::V4(peer_a), 65002), (IpAddr::V4(peer_b), 65003)],
        64,
    );

    state.on_established(
        IpAddr::V4(peer_a),
        peer_a,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(peer_b),
        peer_b,
        PeerType::External,
        65003,
        90,
        &[],
        None,
    );
    while receivers
        .get_mut(&IpAddr::V4(peer_a))
        .unwrap()
        .try_recv()
        .is_ok()
    {}
    while receivers
        .get_mut(&IpAddr::V4(peer_b))
        .unwrap()
        .try_recv()
        .is_ok()
    {}

    // Announce a route from peer_a (buffered into peer_b's pending buffer).
    state.on_route_update(
        IpAddr::V4(peer_a),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(peer_a),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );

    // Before flushing, terminate peer_b — its buffer must be cleared.
    state.on_terminated(IpAddr::V4(peer_b), TerminationReason::Unclean, false);

    // Flush pending: peer_b has no update_sender now, so nothing is sent.
    state.flush_pending();

    // peer_b's channel must remain empty.
    assert!(
        receivers
            .get_mut(&IpAddr::V4(peer_b))
            .unwrap()
            .try_recv()
            .is_err(),
        "terminated peer must not receive buffered decisions after on_terminated"
    );
}

// ── EOR stall regressions ─────────────────────────────────────────────────

/// If the channel is full exactly when the IPv4 EOR would be sent (the dump
/// itself succeeded), the peer must be stalled and eventually stopped.
///
/// Scenario: capacity-1 channel, one route in the Loc-RIB.  The dump
/// consumes the sole slot.  The IPv4 EOR `try_send` then fails, which must
/// push `peer_ip` onto `stalled_peers`.
#[test]
fn eor_stall_when_channel_full_after_dump() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _receivers) = make_capped(&[(peer_ip, 1)], 1);

    let src = PeerId::new(IpAddr::V4("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
    state.rib_insert_v4(
        src,
        base_route(
            "10.0.0.0/8",
            "10.0.0.9".parse().unwrap(),
            PeerType::External,
        ),
    );

    // The dump fills the single slot; EOR try_send fails → stall.
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    assert!(
        state.stalled_peers.contains(&peer_ip),
        "peer must be stalled when the channel is full at EOR time"
    );
}

/// If the IPv4 EOR succeeds but the channel is then full for the IPv6 EOR,
/// the peer must still be stalled.
///
/// Scenario: capacity-2 channel, one route in the Loc-RIB, peer supports
/// IPv6.  Slot 1 = the IPv4 dump UPDATE.  Slot 2 = the IPv4 EOR.  The
/// IPv6 EOR `try_send` has no slot and fails → stall.
#[test]
fn eor_stall_when_ipv6_eor_fails_after_ipv4_eor_succeeds() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    // Capacity 2: slot 1 = IPv4 dump, slot 2 = IPv4 EOR.
    // The IPv6 EOR has no slot and must trigger the stall path.
    let (mut state, _receivers) = make_capped(&[(peer_ip, 2)], 2);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

    let src = PeerId::new(IpAddr::V4("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
    state.rib_insert_v4(
        src,
        base_route(
            "10.0.0.0/8",
            "10.0.0.9".parse().unwrap(),
            PeerType::External,
        ),
    );

    let v6_caps = [Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &v6_caps,
        None,
    );

    assert!(
        state.stalled_peers.contains(&peer_ip),
        "peer must be stalled when IPv6 EOR cannot be sent after successful IPv4 EOR"
    );
}

/// When the channel has enough capacity for the dump AND both EORs, the
/// peer must NOT be stalled.  This is the happy-path complement to the two
/// stall tests above.
#[test]
fn eor_no_stall_when_channel_has_capacity_for_dump_and_eors() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    // Capacity 3: slot 1 = IPv4 dump, slot 2 = IPv4 EOR, slot 3 = IPv6 EOR.
    let (mut state, _receivers) = make_capped(&[(peer_ip, 3)], 3);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

    let src = PeerId::new(IpAddr::V4("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
    state.rib_insert_v4(
        src,
        base_route(
            "10.0.0.0/8",
            "10.0.0.9".parse().unwrap(),
            PeerType::External,
        ),
    );

    let v6_caps = [Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &v6_caps,
        None,
    );

    assert!(
        !state.stalled_peers.contains(&peer_ip),
        "peer must not be stalled when the channel has room for the dump and both EORs"
    );
}

// ── set_export_default propagation loop ───────────────────────────────────

#[test]
fn set_export_default_propagates_to_established_peer() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, mut receivers) = make_capped(&[(peer_ip, 65002)], 64);

    // Populate Loc-RIB BEFORE establishing so the table dump sends the
    // route to peer_ip's Adj-RIB-Out.
    let src = PeerId::new(IpAddr::V4("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
    state.rib_insert_v4(
        src,
        base_route(
            "10.0.0.0/8",
            "10.0.0.9".parse().unwrap(),
            PeerType::External,
        ),
    );

    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    // Drain the table-dump UPDATE so the receiver is clean.
    receivers.get_mut(&peer_ip).unwrap().try_recv().ok();

    // Reject all exports — peer_ip must receive a WITHDRAW.
    state.set_export_default(peer_ip, DefaultAction::Reject);

    receivers
        .get_mut(&peer_ip)
        .unwrap()
        .try_recv()
        .expect("peer must receive WITHDRAW after set_export_default → Reject");
}

#[test]
fn set_export_default_no_send_when_peer_not_established() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, mut receivers) = make_capped(&[(peer_ip, 65002)], 64);

    // Peer is configured but never established — set_export_default must
    // return early without sending anything to the channel.
    let src = PeerId::new(IpAddr::V4("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
    state.rib_insert_v4(
        src,
        base_route(
            "10.0.0.0/8",
            "10.0.0.9".parse().unwrap(),
            PeerType::External,
        ),
    );

    state.set_export_default(peer_ip, DefaultAction::Reject);
    assert!(
        receivers.get_mut(&peer_ip).unwrap().try_recv().is_err(),
        "no message must be sent when peer is not established"
    );
}

#[test]
fn set_export_default_marks_stalled_when_channel_full() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _rx) = make_capped(&[(peer_ip, 65002)], 1);

    // Pre-populate Loc-RIB so the table dump fills the channel (cap 1).
    let src = PeerId::new(IpAddr::V4("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
    state.rib_insert_v4(
        src,
        base_route(
            "10.0.0.0/8",
            "10.0.0.9".parse().unwrap(),
            PeerType::External,
        ),
    );

    // on_established table-dumps the route → fills the cap-1 channel.
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    // Do NOT drain the channel — it is now full.

    // Reject forces a WITHDRAW for the route already in adj_rib_out.
    // try_send(withdraw) finds the channel full → propagate_prefix returns
    // false → peer is pushed into stalled_peers.
    state.set_export_default(peer_ip, DefaultAction::Reject);
    assert!(
        !state.take_stalled_peers().is_empty(),
        "peer must be stalled when channel is full during set_export_default propagation"
    );
}

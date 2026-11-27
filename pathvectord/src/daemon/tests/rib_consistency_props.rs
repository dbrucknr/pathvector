//! Property tests for the RIB consistency invariant: every prefix a peer's
//! `AdjRibOut` (v4 or v6) is currently advertising must also be present in
//! `LocRib` (v4 or v6, respectively). `AdjRibOut` only ever holds routes
//! derived from `LocRib`'s current best path via `propagate_prefix`/
//! `propagate_prefix_v6`, so this must hold after every event-loop operation
//! — a violation would mean a peer is being told about a route pathvectord
//! itself no longer considers valid.
//!
//! Flagged as a coverage gap in TODO.md: "`pathvectord` event-loop
//! transitions don't have proptests yet."

use std::{collections::HashMap, net::Ipv4Addr};

use proptest::prelude::*;
use tokio::sync::mpsc;

use crate::config;
use crate::daemon::*;

fn peer_cfg(address: IpAddr, remote_as: u32) -> config::PeerConfig {
    config::PeerConfig {
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
    }
}

fn peer_ip(idx: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, 2 + idx)
}

fn peer_as(idx: u8) -> u32 {
    65002 + u32::from(idx)
}

fn v4_prefix(idx: u8) -> Nlri<Ipv4Addr> {
    format!("10.50.{idx}.0/24").parse().unwrap()
}

fn v6_prefix(idx: u8) -> Nlri<Ipv6Addr> {
    format!("2001:db8:{idx}::/64").parse().unwrap()
}

/// Three eBGP peers, all established with the IPv6 MultiProtocol
/// capability (so v6 propagation is actually exercised, not silently
/// skipped) and a local IPv6 address configured (required for eBGP v6
/// announcements — see `propagate_prefix_v6`'s doc comment).
fn fresh_state_with_peers() -> DaemonState {
    let peers: Vec<(Ipv4Addr, u32)> = (0u8..3).map(|i| (peer_ip(i), peer_as(i))).collect();
    let mut senders = HashMap::new();
    for &(ip, _) in &peers {
        let (tx, _rx) = mpsc::channel(64);
        senders.insert(IpAddr::V4(ip), tx);
    }
    let cfgs: Vec<config::PeerConfig> = peers
        .iter()
        .map(|&(a, r)| peer_cfg(IpAddr::V4(a), r))
        .collect();
    let mut state = DaemonState::new(
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &cfgs,
        senders,
        vec![],
    );
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

    let v6_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
    for i in 0u8..3 {
        state.on_established(
            IpAddr::V4(peer_ip(i)),
            peer_ip(i),
            PeerType::External,
            peer_as(i),
            90,
            &v6_caps,
            None,
        );
    }
    state
}

fn assert_adj_rib_out_subset_of_loc_rib(s: &DaemonState, label: &str) {
    for (peer_ip, aro) in &s.adj_ribs_out {
        for (nlri, _) in aro.routes() {
            assert!(
                s.rib.loc_rib.best(nlri).is_some(),
                "{label}: peer {peer_ip} adj_ribs_out advertises {nlri:?} \
                 which is not present in loc_rib"
            );
        }
    }
    for (peer_ip, aro6) in &s.adj_ribs_out_v6 {
        for (nlri, _) in aro6.routes() {
            assert!(
                s.rib.loc_rib_v6.best(nlri).is_some(),
                "{label}: peer {peer_ip} adj_ribs_out_v6 advertises {nlri:?} \
                 which is not present in loc_rib_v6"
            );
        }
    }
}

#[derive(Clone, Debug)]
enum Op {
    AnnounceV4 { peer: u8, prefix: u8 },
    WithdrawV4 { peer: u8, prefix: u8 },
    AnnounceV6 { peer: u8, prefix: u8 },
    WithdrawV6 { peer: u8, prefix: u8 },
    OriginateV4 { prefix: u8 },
    WithdrawOriginatedV4 { prefix: u8 },
    OriginateV6 { prefix: u8 },
    WithdrawOriginatedV6 { prefix: u8 },
}

fn op_strategy() -> impl Strategy<Value = Op> {
    let peer = 0u8..=2u8;
    let prefix = 0u8..=2u8;
    prop_oneof![
        (peer.clone(), prefix.clone()).prop_map(|(peer, prefix)| Op::AnnounceV4 { peer, prefix }),
        (peer.clone(), prefix.clone()).prop_map(|(peer, prefix)| Op::WithdrawV4 { peer, prefix }),
        (peer.clone(), prefix.clone()).prop_map(|(peer, prefix)| Op::AnnounceV6 { peer, prefix }),
        (peer, prefix.clone()).prop_map(|(peer, prefix)| Op::WithdrawV6 { peer, prefix }),
        prefix.clone().prop_map(|prefix| Op::OriginateV4 { prefix }),
        prefix
            .clone()
            .prop_map(|prefix| Op::WithdrawOriginatedV4 { prefix }),
        prefix.clone().prop_map(|prefix| Op::OriginateV6 { prefix }),
        prefix.prop_map(|prefix| Op::WithdrawOriginatedV6 { prefix }),
    ]
}

proptest! {
    /// Any sequence of up to 30 announce/withdraw/originate operations
    /// (v4 and v6, from any of 3 peers, over any of 3 prefixes per
    /// family) must leave every peer's AdjRibOut a subset of LocRib.
    #[test]
    fn prop_adj_rib_out_always_subset_of_loc_rib(
        ops in prop::collection::vec(op_strategy(), 1..=30)
    ) {
        let mut state = fresh_state_with_peers();
        assert_adj_rib_out_subset_of_loc_rib(&state, "initial");

        for (i, op) in ops.iter().enumerate() {
            match op {
                Op::AnnounceV4 { peer, prefix } => {
                    let msg = UpdateMessage {
                        withdrawn: vec![],
                        attributes: vec![
                            PathAttribute::Origin(Origin::Igp),
                            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(peer_as(*peer))])),
                            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 100 + *peer)),
                        ],
                        announced: vec![v4_prefix(*prefix)],
                    };
                    state.on_route_update(IpAddr::V4(peer_ip(*peer)), msg);
                    state.flush_pending();
                }
                Op::WithdrawV4 { peer, prefix } => {
                    let msg = UpdateMessage {
                        withdrawn: vec![v4_prefix(*prefix)],
                        attributes: vec![],
                        announced: vec![],
                    };
                    state.on_route_update(IpAddr::V4(peer_ip(*peer)), msg);
                    state.flush_pending();
                }
                Op::AnnounceV6 { peer, prefix } => {
                    let msg = UpdateMessage {
                        withdrawn: vec![],
                        attributes: vec![
                            PathAttribute::Origin(Origin::Igp),
                            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(peer_as(*peer))])),
                            PathAttribute::MpReachNlri(MpReachNlri {
                                afi_safi: AfiSafi::IPV6_UNICAST,
                                next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                                prefixes: vec![Prefix::V6(v6_prefix(*prefix))],
                            }),
                        ],
                        announced: vec![],
                    };
                    state.on_route_update(IpAddr::V4(peer_ip(*peer)), msg);
                    state.flush_pending();
                }
                Op::WithdrawV6 { peer, prefix } => {
                    let msg = UpdateMessage {
                        withdrawn: vec![],
                        attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                            afi_safi: AfiSafi::IPV6_UNICAST,
                            prefixes: vec![Prefix::V6(v6_prefix(*prefix))],
                        })],
                        announced: vec![],
                    };
                    state.on_route_update(IpAddr::V4(peer_ip(*peer)), msg);
                    state.flush_pending();
                }
                Op::OriginateV4 { prefix } => {
                    let route = RouteBuilder::new(v4_prefix(*prefix), Origin::Igp, AsPath::new())
                        .next_hop(NextHop::V4(Ipv4Addr::new(192, 0, 2, 1)))
                        .build();
                    state.originate_route(route);
                }
                Op::WithdrawOriginatedV4 { prefix } => {
                    state.withdraw_originated_route(v4_prefix(*prefix));
                }
                Op::OriginateV6 { prefix } => {
                    let route = RouteBuilder::new(v6_prefix(*prefix), Origin::Igp, AsPath::new())
                        .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
                        .build();
                    state.originate_route_v6(route);
                }
                Op::WithdrawOriginatedV6 { prefix } => {
                    state.withdraw_originated_route_v6(v6_prefix(*prefix));
                }
            }
            assert_adj_rib_out_subset_of_loc_rib(&state, &format!("after op {i}: {op:?}"));
        }
    }
}

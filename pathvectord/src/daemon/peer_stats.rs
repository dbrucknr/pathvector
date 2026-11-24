//! Read port for per-peer prefix counts (issue #106).
//!
//! `list_peers`, `get_peer` and `watch_peers` report, for each peer, how many
//! prefixes it sent, how many of those won best-path selection, and how many
//! were advertised to it. They used to compute "won" by scanning the whole
//! Loc-RIB once per peer, under a cloned `Arc<RibSnapshot>` that forced a
//! copy-on-write RIB clone whenever the event loop mutated at the same time.
//!
//! All three numbers are now O(1) lookups: `received` and `advertised` are
//! derived counters on the snapshot, and `accepted` is
//! [`LocRib::best_win_count`](pathvector_rib::LocRib::best_win_count), which
//! the RIB maintains where a prefix's winner changes and so cannot drift.
//! The gRPC layer sees only [`PeerRibStats`], never the RIB's internals, and
//! none of this code mutates anything.

use std::net::IpAddr;

use pathvector_rib::PeerId;

use super::RibSnapshot;

/// A prefix count on its way to a `uint32` proto field.
///
/// Counts live as `usize` inside the daemon; the wire type is `u32`.
/// [`PrefixCount::saturating`] is the one conversion, so an (unrealistic)
/// table beyond `u32::MAX` reports the maximum instead of wrapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrefixCount(u32);

impl PrefixCount {
    pub(crate) fn saturating(n: usize) -> Self {
        Self(u32::try_from(n).unwrap_or(u32::MAX))
    }

    pub(crate) fn get(self) -> u32 {
        self.0
    }
}

/// Per-peer prefix counts as reported by the management API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerRibStats {
    /// Prefixes in the peer's Adj-RIB-In (IPv4 + IPv6).
    pub(crate) received: PrefixCount,
    /// Loc-RIB prefixes whose best path is this peer's (IPv4 + IPv6).
    pub(crate) accepted: PrefixCount,
    /// Prefixes in the peer's Adj-RIB-Out (IPv4 + IPv6).
    pub(crate) advertised: PrefixCount,
}

impl RibSnapshot {
    /// Prefix counts for `addr`. O(1): no Loc-RIB scan, no allocation.
    pub(crate) fn peer_rib_stats(&self, addr: IpAddr) -> PeerRibStats {
        let peer = PeerId::from(addr);
        let received = self.prefixes_received.get(&addr).copied().unwrap_or(0);
        let advertised = self.prefixes_advertised.get(&addr).copied().unwrap_or(0);
        let accepted = self.loc_rib.best_win_count(&peer) + self.loc_rib_v6.best_win_count(&peer);
        PeerRibStats {
            received: PrefixCount::saturating(received),
            accepted: PrefixCount::saturating(accepted),
            advertised: PrefixCount::saturating(advertised),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        net::{Ipv4Addr, Ipv6Addr},
        sync::Arc,
    };

    use pathvector_rib::RouteBuilder;
    use pathvector_session::{
        message::{Capability, MpReachNlri, MpUnreachNlri, PathAttribute, Prefix, UpdateMessage},
        transport::TerminationReason,
    };
    use pathvector_types::{AfiSafi, AsPath, Asn, NextHop, Nlri, Origin, PeerType};
    use proptest::prelude::*;
    use tokio::sync::mpsc;

    use super::*;
    use crate::{DaemonState, config};

    #[test]
    fn prefix_count_saturates_instead_of_wrapping() {
        assert_eq!(PrefixCount::saturating(0).get(), 0);
        assert_eq!(PrefixCount::saturating(u32::MAX as usize).get(), u32::MAX);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            PrefixCount::saturating(u32::MAX as usize + 1).get(),
            u32::MAX
        );
    }

    // ── daemon-level invariant (issue #106) ───────────────────────────────────
    //
    // `accepted` is the Loc-RIB's incremental win count. Drive a real
    // `DaemonState` through its production mutation paths — import policy,
    // best-path selection, withdrawal, session teardown with Loc-RIB flush,
    // re-establishment — and require after every step that each peer's
    // reported `accepted` equals a from-scratch scan of both Loc-RIBs.

    const PEERS: u8 = 3;

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

    fn peer_cfg(idx: u8) -> config::PeerConfig {
        config::PeerConfig {
            address: IpAddr::V4(peer_ip(idx)),
            port: 179,
            remote_as: peer_as(idx),
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
        }
    }

    fn establish(state: &mut DaemonState, idx: u8) {
        state.on_established(
            IpAddr::V4(peer_ip(idx)),
            peer_ip(idx),
            PeerType::External,
            peer_as(idx),
            90,
            &[Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)],
            None,
        );
    }

    fn fresh_state() -> DaemonState {
        let mut senders = HashMap::new();
        for i in 0..PEERS {
            let (tx, _rx) = mpsc::channel(64);
            senders.insert(IpAddr::V4(peer_ip(i)), tx);
        }
        let cfgs: Vec<config::PeerConfig> = (0..PEERS).map(peer_cfg).collect();
        let mut state = DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            None,
            &cfgs,
            senders,
            vec![],
        );
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());
        for i in 0..PEERS {
            establish(&mut state, i);
        }
        state
    }

    #[derive(Clone, Debug)]
    enum Op {
        AnnounceV4 { peer: u8, prefix: u8, path_len: u8 },
        WithdrawV4 { peer: u8, prefix: u8 },
        AnnounceV6 { peer: u8, prefix: u8, path_len: u8 },
        WithdrawV6 { peer: u8, prefix: u8 },
        Teardown { peer: u8 },
        Reestablish { peer: u8 },
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        let peer = 0..PEERS;
        let prefix = 0u8..=2;
        // A longer AS_PATH loses, so differing lengths make the winner move
        // between peers instead of always being the lowest peer address.
        let path_len = 1u8..=3;
        prop_oneof![
            4 => (peer.clone(), prefix.clone(), path_len.clone())
                .prop_map(|(peer, prefix, path_len)| Op::AnnounceV4 { peer, prefix, path_len }),
            2 => (peer.clone(), prefix.clone())
                .prop_map(|(peer, prefix)| Op::WithdrawV4 { peer, prefix }),
            4 => (peer.clone(), prefix.clone(), path_len)
                .prop_map(|(peer, prefix, path_len)| Op::AnnounceV6 { peer, prefix, path_len }),
            2 => (peer.clone(), prefix)
                .prop_map(|(peer, prefix)| Op::WithdrawV6 { peer, prefix }),
            1 => peer.clone().prop_map(|peer| Op::Teardown { peer }),
            1 => peer.prop_map(|peer| Op::Reestablish { peer }),
        ]
    }

    fn as_path(peer: u8, len: u8) -> AsPath {
        let mut asns = vec![Asn::new(peer_as(peer))];
        asns.extend((1..len).map(|n| Asn::new(64_000 + u32::from(n))));
        AsPath::from_sequence(asns)
    }

    /// Independent recount through public Loc-RIB iteration only.
    fn scanned_wins(state: &DaemonState, addr: IpAddr) -> usize {
        let peer = PeerId::from(addr);
        let rib = &state.rib;
        rib.loc_rib
            .best_routes()
            .filter(|(n, _)| rib.loc_rib.best_peer(n) == Some(peer))
            .count()
            + rib
                .loc_rib_v6
                .best_routes()
                .filter(|(n, _)| rib.loc_rib_v6.best_peer(n) == Some(peer))
                .count()
    }

    fn assert_stats_match_recount(state: &DaemonState, label: &str) {
        assert!(
            state.rib.loc_rib.best_win_counts_consistent()
                && state.rib.loc_rib_v6.best_win_counts_consistent(),
            "{label}: internal win-count audit failed"
        );
        for i in 0..PEERS {
            let addr = IpAddr::V4(peer_ip(i));
            let reported = state.rib.peer_rib_stats(addr);
            assert_eq!(
                reported.accepted.get() as usize,
                scanned_wins(state, addr),
                "{label}: accepted for {addr} drifted from a full recount"
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn prop_accepted_count_matches_full_recount_through_daemon_paths(
            ops in prop::collection::vec(op_strategy(), 1..=40)
        ) {
            let mut state = fresh_state();
            let mut up = [true; PEERS as usize];

            for (i, op) in ops.iter().enumerate() {
                match *op {
                    Op::AnnounceV4 { peer, prefix, path_len } if up[peer as usize] => {
                        state.on_route_update(IpAddr::V4(peer_ip(peer)), UpdateMessage {
                            withdrawn: vec![],
                            attributes: vec![
                                PathAttribute::Origin(Origin::Igp),
                                PathAttribute::AsPath(as_path(peer, path_len)),
                                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 100 + peer)),
                            ],
                            announced: vec![v4_prefix(prefix)],
                        });
                    }
                    Op::WithdrawV4 { peer, prefix } if up[peer as usize] => {
                        state.on_route_update(IpAddr::V4(peer_ip(peer)), UpdateMessage {
                            withdrawn: vec![v4_prefix(prefix)],
                            attributes: vec![],
                            announced: vec![],
                        });
                    }
                    Op::AnnounceV6 { peer, prefix, path_len } if up[peer as usize] => {
                        state.on_route_update(IpAddr::V4(peer_ip(peer)), UpdateMessage {
                            withdrawn: vec![],
                            attributes: vec![
                                PathAttribute::Origin(Origin::Igp),
                                PathAttribute::AsPath(as_path(peer, path_len)),
                                PathAttribute::MpReachNlri(MpReachNlri {
                                    afi_safi: AfiSafi::IPV6_UNICAST,
                                    next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                                    prefixes: vec![Prefix::V6(v6_prefix(prefix))],
                                }),
                            ],
                            announced: vec![],
                        });
                    }
                    Op::WithdrawV6 { peer, prefix } if up[peer as usize] => {
                        state.on_route_update(IpAddr::V4(peer_ip(peer)), UpdateMessage {
                            withdrawn: vec![],
                            attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                                afi_safi: AfiSafi::IPV6_UNICAST,
                                prefixes: vec![Prefix::V6(v6_prefix(prefix))],
                            })],
                            announced: vec![],
                        });
                    }
                    Op::Teardown { peer } if up[peer as usize] => {
                        state.on_terminated(
                            IpAddr::V4(peer_ip(peer)),
                            TerminationReason::OperatorStop,
                            false,
                        );
                        up[peer as usize] = false;
                    }
                    Op::Reestablish { peer } if !up[peer as usize] => {
                        establish(&mut state, peer);
                        up[peer as usize] = true;
                    }
                    // Op not applicable to the peer's current session state.
                    _ => {}
                }
                state.flush_pending();
                assert_stats_match_recount(&state, &format!("after op {i}: {op:?}"));
            }
        }
    }

    /// Locally originated routes are keyed by `LOCAL_ORIGIN_PEER`, which is
    /// not a configured peer: they must neither inflate a real peer's count
    /// nor break the audit.
    #[test]
    fn originated_routes_do_not_count_for_configured_peers() {
        let mut state = fresh_state();
        let route = RouteBuilder::new(v4_prefix(0), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(Ipv4Addr::new(192, 0, 2, 1)))
            .build();
        state.originate_route(route);
        assert_stats_match_recount(&state, "after originate");
        for i in 0..PEERS {
            let reported = state.rib.peer_rib_stats(IpAddr::V4(peer_ip(i)));
            assert_eq!(reported.accepted.get(), 0);
        }
    }
}

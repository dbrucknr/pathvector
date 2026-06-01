mod config;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use pathvector_policy::{Decision, DefaultAction, Policy};
use pathvector_rib::{LocRib, PeerId, RouteBuilder};
use pathvector_session::{
    message::{Capability, PathAttribute, UpdateMessage},
    transport::{self, SessionConfig, SessionEvent},
};
use pathvector_types::{AsPath, LocalPref, Med, NextHop, Origin, PeerType};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: pathvectord <config.toml>");
        std::process::exit(1);
    });

    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("failed to read {path}: {e}");
        std::process::exit(1);
    });

    let cfg: config::Config = toml::from_str(&text).unwrap_or_else(|e| {
        eprintln!("failed to parse config: {e}");
        std::process::exit(1);
    });

    run(cfg).await;
}

fn build_import_policy(default: DefaultAction) -> Policy<pathvector_rib::Route<Ipv4Addr>> {
    Policy::new(default)
}

async fn run(cfg: config::Config) {
    let mut rib: LocRib<Ipv4Addr> = LocRib::new();
    let (event_tx, mut event_rx) = mpsc::channel::<(Ipv4Addr, SessionEvent)>(256);

    // Per-peer import policies, keyed by peer IP. Built once at startup from config.
    let import_policies: HashMap<Ipv4Addr, Policy<pathvector_rib::Route<Ipv4Addr>>> = cfg
        .peers
        .iter()
        .map(|p| {
            let default = DefaultAction::from(p.import_default);
            (p.address, build_import_policy(default))
        })
        .collect();

    for peer in &cfg.peers {
        let session_cfg = SessionConfig {
            local_as: cfg.daemon.local_as,
            local_bgp_id: cfg.daemon.bgp_id,
            hold_time: cfg.daemon.hold_time,
            capabilities: vec![Capability::FourByteAsn(cfg.daemon.local_as)],
            peer_as: Some(peer.remote_as),
            peer_addr: SocketAddr::new(IpAddr::V4(peer.address), peer.port),
        };

        let mut handle = transport::spawn(session_cfg);
        handle.start().await;

        let peer_addr = peer.address;
        let tx = event_tx.clone();
        tokio::spawn(async move {
            while let Some(event) = handle.next_event().await {
                if tx.send((peer_addr, event)).await.is_err() {
                    break;
                }
            }
        });
    }
    // Drop our sender copy so the channel closes when all peer tasks exit.
    drop(event_tx);

    // Session-type cache: populated from SessionInfo on Established, cleared on Terminated.
    let mut peer_types: HashMap<Ipv4Addr, PeerType> = HashMap::new();

    while let Some((peer_ip, event)) = event_rx.recv().await {
        let peer_id = PeerId::from(peer_ip);
        match event {
            SessionEvent::Established(info) => {
                peer_types.insert(peer_ip, info.peer_type);
                tracing::info!(
                    peer = %peer_ip,
                    remote_as = info.peer_as,
                    hold_time = info.hold_time,
                    peer_type = %info.peer_type,
                    "session established"
                );
            }
            SessionEvent::Terminated => {
                peer_types.remove(&peer_ip);
                tracing::info!(peer = %peer_ip, "session terminated");
                rib.withdraw_peer(&peer_id);
                tracing::info!(rib_size = rib.len(), "RIB updated after peer teardown");
            }
            SessionEvent::RouteUpdate(msg) => {
                let peer_type = peer_types.get(&peer_ip).copied().unwrap_or(PeerType::External);
                // import_policies is built from cfg.peers at startup so every peer has an entry.
                let policy = import_policies.get(&peer_ip)
                    .expect("peer IP missing from import_policies — this is a bug");
                handle_update(peer_id, msg, &mut rib, policy, peer_type);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use pathvector_policy::{
        AnyCondition, DefaultAction, Policy, Term, Accept, Reject,
        ActionSequence, SetLocalPref,
    };
    use pathvector_types::{Aggregator, Asn, Community, ExtendedCommunity, LargeCommunity, LocalPref as LP, Nlri};

    use super::*;

    fn peer() -> PeerId {
        PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    }

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn accept_all() -> Policy<pathvector_rib::Route<Ipv4Addr>> {
        Policy::new(DefaultAction::Accept)
    }

    fn reject_all() -> Policy<pathvector_rib::Route<Ipv4Addr>> {
        Policy::new(DefaultAction::Reject)
    }

    #[test]
    fn test_handle_update_inserts_route_with_all_attributes() {
        let mut rib = LocRib::new();
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Egp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                PathAttribute::LocalPref(200),
                PathAttribute::Med(50),
                PathAttribute::Communities(vec![Community::new(0x0001_0001)]),
                PathAttribute::LargeCommunities(vec![LargeCommunity::new(65000, 1, 100)]),
                PathAttribute::ExtendedCommunities(vec![
                    ExtendedCommunity::route_target_as2(65000, 1),
                ]),
                PathAttribute::AtomicAggregate,
                PathAttribute::Aggregator(Aggregator::new(
                    Asn::new(65001),
                    Ipv4Addr::new(1, 1, 1, 1),
                )),
            ],
            announced: vec![nlri("192.168.0.0/16")],
        };
        handle_update(peer(), msg, &mut rib, &accept_all(), PeerType::External);

        let route = rib.best(&nlri("192.168.0.0/16")).unwrap();
        assert_eq!(route.origin, Origin::Egp);
        assert_eq!(route.local_pref, Some(LocalPref::new(200)));
        assert_eq!(route.med, Some(Med::new(50)));
        assert_eq!(route.communities.len(), 1);
        assert_eq!(route.large_communities.len(), 1);
        assert_eq!(route.extended_communities.len(), 1);
        assert!(route.atomic_aggregate);
        assert!(route.aggregator.is_some());
    }

    #[test]
    fn test_handle_update_withdraw_removes_route() {
        let mut rib = LocRib::new();
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 1);

        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![nlri("10.0.0.0/8")],
                attributes: vec![],
                announced: vec![],
            },
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(rib.is_empty());
    }

    #[test]
    fn test_handle_update_empty_announced_is_noop() {
        let mut rib = LocRib::new();
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::Origin(Origin::Igp)],
                announced: vec![],
            },
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(rib.is_empty());
    }

    #[test]
    fn test_handle_update_unknown_attribute_is_skipped() {
        let mut rib = LocRib::new();
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::Unknown { flags: 0x80, type_code: 255, value: vec![1, 2, 3] },
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 1);
    }

    // ── import policy ─────────────────────────────────────────────────────────

    #[test]
    fn test_reject_all_policy_blocks_all_routes() {
        let mut rib = LocRib::new();
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8"), nlri("192.168.0.0/16")],
            },
            &mut rib,
            &reject_all(),
            PeerType::External,
        );
        assert!(rib.is_empty());
    }

    #[test]
    fn test_accept_all_policy_passes_all_routes() {
        let mut rib = LocRib::new();
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8"), nlri("192.168.0.0/16")],
            },
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 2);
    }

    #[test]
    fn test_policy_modifies_route_before_insert() {
        // A term that sets LOCAL_PREF 200 on every accepted route.
        let mut policy: Policy<pathvector_rib::Route<Ipv4Addr>> =
            Policy::new(DefaultAction::Reject);
        policy.add_term(Term::new(
            AnyCondition,
            ActionSequence::new()
                .then(SetLocalPref::new(LP::new(200)))
                .then(Accept),
        ));

        let mut rib = LocRib::new();
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut rib,
            &policy,
            PeerType::External,
        );

        let route = rib.best(&nlri("10.0.0.0/8")).unwrap();
        assert_eq!(route.local_pref, Some(LP::new(200)));
    }

    #[test]
    fn test_policy_partial_reject_only_accepted_routes_inserted() {
        // Reject routes with communities 65001:1, accept everything else.
        let blocked = Community::from_parts(65001, 1);
        let mut policy: Policy<pathvector_rib::Route<Ipv4Addr>> =
            Policy::new(DefaultAction::Accept);
        policy.add_term(Term::new(
            pathvector_policy::CommunityCondition::new(blocked),
            Reject,
        ));

        let mut rib = LocRib::new();

        // Route tagged with the blocked community.
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::Communities(vec![blocked]),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut rib,
            &policy,
            PeerType::External,
        );

        // Clean route — no blocked community.
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("192.168.0.0/16")],
            },
            &mut rib,
            &policy,
            PeerType::External,
        );

        assert!(rib.best(&nlri("10.0.0.0/8")).is_none(), "blocked route must not be in RIB");
        assert!(rib.best(&nlri("192.168.0.0/16")).is_some(), "clean route must be in RIB");
    }

    #[test]
    fn test_peer_type_tagged_on_route() {
        let mut rib = LocRib::new();
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut rib,
            &accept_all(),
            PeerType::Internal,
        );
        let route = rib.best(&nlri("10.0.0.0/8")).unwrap();
        assert_eq!(route.peer_type, PeerType::Internal);
    }
}

fn handle_update(
    peer: PeerId,
    msg: UpdateMessage,
    rib: &mut LocRib<Ipv4Addr>,
    policy: &Policy<pathvector_rib::Route<Ipv4Addr>>,
    peer_type: PeerType,
) {
    let withdrawn_count = msg.withdrawn.len();
    let announced_count = msg.announced.len();

    for nlri in &msg.withdrawn {
        rib.withdraw(&peer, nlri);
    }

    let mut accepted = 0usize;
    let mut rejected = 0usize;

    if announced_count > 0 {
        let mut origin = Origin::Incomplete;
        let mut as_path = AsPath::new();
        let mut next_hop: Option<NextHop> = None;
        let mut local_pref: Option<LocalPref> = None;
        let mut med: Option<Med> = None;
        let mut communities = Vec::new();
        let mut large_communities = Vec::new();
        let mut extended_communities = Vec::new();
        let mut atomic_aggregate = false;
        let mut aggregator = None;

        for attr in &msg.attributes {
            match attr {
                PathAttribute::Origin(o) => origin = *o,
                PathAttribute::AsPath(p) => as_path = p.clone(),
                PathAttribute::NextHop(ip) => next_hop = Some(NextHop::V4(*ip)),
                PathAttribute::LocalPref(lp) => local_pref = Some(LocalPref::new(*lp)),
                PathAttribute::Med(m) => med = Some(Med::new(*m)),
                PathAttribute::Communities(cs) => communities.clone_from(cs),
                PathAttribute::LargeCommunities(lcs) => large_communities.clone_from(lcs),
                PathAttribute::ExtendedCommunities(ecs) => extended_communities.clone_from(ecs),
                PathAttribute::AtomicAggregate => atomic_aggregate = true,
                PathAttribute::Aggregator(a) => aggregator = Some(*a),
                _ => {}
            }
        }

        for nlri in msg.announced {
            let mut builder = RouteBuilder::new(nlri, origin, as_path.clone())
                .peer_type(peer_type);
            if let Some(nh) = next_hop {
                builder = builder.next_hop(nh);
            }
            if let Some(lp) = local_pref {
                builder = builder.local_pref(lp);
            }
            if let Some(m) = med {
                builder = builder.med(m);
            }
            for &c in &communities {
                builder = builder.community(c);
            }
            for &lc in &large_communities {
                builder = builder.large_community(lc);
            }
            for &ec in &extended_communities {
                builder = builder.extended_community(ec);
            }
            if atomic_aggregate {
                builder = builder.atomic_aggregate();
            }
            if let Some(agg) = aggregator {
                builder = builder.aggregator(agg);
            }

            let mut route = builder.build();
            match policy.evaluate(&mut route) {
                Decision::Accept => {
                    rib.insert(peer, route);
                    accepted += 1;
                }
                Decision::Reject | Decision::Next => {
                    rejected += 1;
                }
            }
        }
    }

    tracing::info!(
        peer = %peer,
        withdrawn = withdrawn_count,
        accepted,
        rejected,
        rib_size = rib.len(),
        "processed UPDATE"
    );
}

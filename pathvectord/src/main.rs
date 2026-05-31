mod config;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use pathvector_rib::{LocRib, PeerId, RouteBuilder};
use pathvector_session::{
    message::{Capability, PathAttribute, UpdateMessage},
    transport::{self, SessionConfig, SessionEvent},
};
use pathvector_types::{AsPath, LocalPref, Med, NextHop, Origin};
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

async fn run(cfg: config::Config) {
    let mut rib: LocRib<Ipv4Addr> = LocRib::new();
    let (event_tx, mut event_rx) = mpsc::channel::<(Ipv4Addr, SessionEvent)>(256);

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

    while let Some((peer_ip, event)) = event_rx.recv().await {
        let peer_id = PeerId::from(peer_ip);
        match event {
            SessionEvent::Established(info) => {
                tracing::info!(
                    peer = %peer_ip,
                    remote_as = info.peer_as,
                    hold_time = info.hold_time,
                    "session established"
                );
            }
            SessionEvent::Terminated => {
                tracing::info!(peer = %peer_ip, "session terminated");
                rib.withdraw_peer(&peer_id);
                tracing::info!(rib_size = rib.len(), "RIB updated after peer teardown");
            }
            SessionEvent::RouteUpdate(msg) => {
                handle_update(peer_id, msg, &mut rib);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use pathvector_types::{Aggregator, Asn, Community, ExtendedCommunity, LargeCommunity, Nlri};

    use super::*;

    fn peer() -> PeerId {
        PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    }

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
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
        handle_update(peer(), msg, &mut rib);

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
        );
        assert_eq!(rib.len(), 1);
    }
}

fn handle_update(peer: PeerId, msg: UpdateMessage, rib: &mut LocRib<Ipv4Addr>) {
    let withdrawn_count = msg.withdrawn.len();
    let announced_count = msg.announced.len();

    for nlri in &msg.withdrawn {
        rib.withdraw(&peer, nlri);
    }

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
            let mut builder = RouteBuilder::new(nlri, origin, as_path.clone());
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
            rib.insert(peer, builder.build());
        }
    }

    tracing::info!(
        peer = %peer,
        withdrawn = withdrawn_count,
        announced = announced_count,
        rib_size = rib.len(),
        "processed UPDATE"
    );
}

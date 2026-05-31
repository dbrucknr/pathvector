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

mod config;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use pathvector_policy::{Decision, DefaultAction, Policy};
use pathvector_rib::{AdjRibIn, AdjRibOut, InsertOutcome, LocRib, PeerId, Route, RouteBuilder};
use pathvector_session::{
    message::{Capability, PathAttribute, UpdateMessage},
    transport::{self, SessionConfig, SessionEvent},
};
use pathvector_types::{AsPath, Asn, LocalPref, Med, NextHop, Nlri, Origin, PeerType};
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

fn build_import_policy(default: DefaultAction) -> Policy<Route<Ipv4Addr>> {
    Policy::new(default)
}

fn build_export_policy(default: DefaultAction) -> Policy<Route<Ipv4Addr>> {
    Policy::new(default)
}

/// Derives the peer type (iBGP / eBGP) from the configured AS numbers.
fn config_peer_type(local_as: u32, remote_as: u32) -> PeerType {
    if local_as == remote_as {
        PeerType::Internal
    } else {
        PeerType::External
    }
}

/// Applies eBGP outbound transforms to a route clone before insertion into
/// `AdjRibOut` or serialisation into an UPDATE message:
///
/// - Prepend local AS to `AS_PATH` (RFC 4271 §9.2.1.2)
/// - Rewrite `NEXT_HOP` to the local BGP identifier (RFC 4271 §5.1.3)
/// - Strip `LOCAL_PREF` (RFC 4271 §5.1.5 — must not be sent to eBGP peers)
///
/// iBGP peers receive the route unmodified; confederation segment stripping
/// for eBGP is handled separately by `AdjRibOut::insert`.
fn prepare_outbound(
    mut route: Route<Ipv4Addr>,
    peer_type: PeerType,
    local_as: u32,
    local_bgp_id: Ipv4Addr,
) -> Route<Ipv4Addr> {
    if peer_type == PeerType::External {
        route.as_path.prepend(Asn::new(local_as));
        route.next_hop = Some(NextHop::V4(local_bgp_id));
        route.local_pref = None;
    }
    route
}

/// Serialises a post-policy, post-transform route into a BGP UPDATE message
/// with a single announced NLRI.
fn route_to_update(route: Route<Ipv4Addr>) -> UpdateMessage {
    let mut attributes = vec![
        PathAttribute::Origin(route.origin),
        PathAttribute::AsPath(route.as_path),
    ];
    if let Some(NextHop::V4(nh)) = route.next_hop {
        attributes.push(PathAttribute::NextHop(nh));
    }
    if let Some(lp) = route.local_pref {
        attributes.push(PathAttribute::LocalPref(lp.as_u32()));
    }
    if let Some(m) = route.med {
        attributes.push(PathAttribute::Med(m.as_u32()));
    }
    if !route.communities.is_empty() {
        attributes.push(PathAttribute::Communities(route.communities));
    }
    if !route.large_communities.is_empty() {
        attributes.push(PathAttribute::LargeCommunities(route.large_communities));
    }
    if !route.extended_communities.is_empty() {
        attributes.push(PathAttribute::ExtendedCommunities(
            route.extended_communities,
        ));
    }
    if route.atomic_aggregate {
        attributes.push(PathAttribute::AtomicAggregate);
    }
    if let Some(agg) = route.aggregator {
        attributes.push(PathAttribute::Aggregator(agg));
    }
    UpdateMessage {
        withdrawn: vec![],
        attributes,
        announced: vec![route.nlri],
    }
}

fn withdraw_msg(nlri: Nlri<Ipv4Addr>) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![nlri],
        attributes: vec![],
        announced: vec![],
    }
}

/// Propagates the current best route for `nlri` to one peer's outbound table.
///
/// Reads the current best from `loc_rib`, applies export policy, runs eBGP
/// attribute transforms via `prepare_outbound`, and calls `AdjRibOut::insert`.
/// Sends an UPDATE or WITHDRAW only when the advertised state actually changes,
/// so this function is safe to call even if the best route did not change.
///
/// Only call this for established peers; `update_tx` for non-established peers
/// is not drained until they come up, which can produce stale advertisements.
#[allow(clippy::too_many_arguments)]
fn propagate_prefix(
    nlri: Nlri<Ipv4Addr>,
    loc_rib: &LocRib<Ipv4Addr>,
    adj_rib_out: &mut AdjRibOut<Ipv4Addr>,
    export_policy: &Policy<Route<Ipv4Addr>>,
    peer_type: PeerType,
    local_as: u32,
    local_bgp_id: Ipv4Addr,
    update_tx: &mpsc::Sender<UpdateMessage>,
) {
    match loc_rib.best(&nlri) {
        Some(best) => {
            let mut route = prepare_outbound(best.clone(), peer_type, local_as, local_bgp_id);
            match export_policy.evaluate(&mut route) {
                Decision::Accept => {
                    match adj_rib_out.insert(route.clone()) {
                        InsertOutcome::Accepted(prev) => {
                            if prev.as_ref() != Some(&route)
                                && update_tx.try_send(route_to_update(route)).is_err()
                            {
                                tracing::warn!(
                                    peer = %adj_rib_out.peer(),
                                    prefix = %nlri,
                                    "outbound UPDATE channel full, dropping"
                                );
                            }
                        }
                        InsertOutcome::Filtered(Some(_)) => {
                            // iBGP split-horizon evicted a previously stored route.
                            if update_tx.try_send(withdraw_msg(nlri)).is_err() {
                                tracing::warn!(
                                    peer = %adj_rib_out.peer(),
                                    prefix = %nlri,
                                    "outbound WITHDRAW channel full, dropping"
                                );
                            }
                        }
                        InsertOutcome::Filtered(None) => {}
                    }
                }
                Decision::Reject | Decision::Next => {
                    if adj_rib_out.withdraw(&nlri).is_some()
                        && update_tx.try_send(withdraw_msg(nlri)).is_err()
                    {
                        tracing::warn!(
                            peer = %adj_rib_out.peer(),
                            prefix = %nlri,
                            "outbound WITHDRAW channel full, dropping"
                        );
                    }
                }
            }
        }
        None => {
            if adj_rib_out.withdraw(&nlri).is_some()
                && update_tx.try_send(withdraw_msg(nlri)).is_err()
            {
                tracing::warn!(
                    peer = %adj_rib_out.peer(),
                    prefix = %nlri,
                    "outbound WITHDRAW channel full, dropping"
                );
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run(cfg: config::Config) {
    let local_as = cfg.daemon.local_as;
    let local_bgp_id = cfg.daemon.bgp_id;

    let mut loc_rib: LocRib<Ipv4Addr> = LocRib::new();
    let (event_tx, mut event_rx) = mpsc::channel::<(Ipv4Addr, SessionEvent)>(256);

    // Per-peer tables and policies, all keyed by peer IP and built from config
    // at startup so every peer always has an entry.
    let import_policies: HashMap<Ipv4Addr, Policy<Route<Ipv4Addr>>> = cfg
        .peers
        .iter()
        .map(|p| {
            (
                p.address,
                build_import_policy(DefaultAction::from(p.import_default)),
            )
        })
        .collect();

    let export_policies: HashMap<Ipv4Addr, Policy<Route<Ipv4Addr>>> = cfg
        .peers
        .iter()
        .map(|p| {
            (
                p.address,
                build_export_policy(DefaultAction::from(p.export_default)),
            )
        })
        .collect();

    let mut adj_ribs_in_map: HashMap<Ipv4Addr, AdjRibIn<Ipv4Addr>> = cfg
        .peers
        .iter()
        .map(|p| (p.address, AdjRibIn::new(PeerId::from(p.address))))
        .collect();

    // Derived at config load and used to reset AdjRibOut on session termination.
    let peer_config_types: HashMap<Ipv4Addr, PeerType> = cfg
        .peers
        .iter()
        .map(|p| (p.address, config_peer_type(local_as, p.remote_as)))
        .collect();

    let mut adj_ribs_out_map: HashMap<Ipv4Addr, AdjRibOut<Ipv4Addr>> = cfg
        .peers
        .iter()
        .map(|p| {
            let pt = config_peer_type(local_as, p.remote_as);
            (p.address, AdjRibOut::new(PeerId::from(p.address), pt))
        })
        .collect();

    // Per-peer senders for queuing outbound UPDATEs; extracted before the
    // handle is moved into the event-relay task.
    let mut update_senders: HashMap<Ipv4Addr, mpsc::Sender<UpdateMessage>> = HashMap::new();

    for peer in &cfg.peers {
        let session_cfg = SessionConfig {
            local_as,
            local_bgp_id,
            hold_time: cfg.daemon.hold_time,
            capabilities: vec![Capability::FourByteAsn(local_as)],
            peer_as: Some(peer.remote_as),
            peer_addr: SocketAddr::new(IpAddr::V4(peer.address), peer.port),
        };

        let mut handle = transport::spawn(session_cfg);
        handle.start().await;

        update_senders.insert(peer.address, handle.update_sender());

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

                // Reset AdjRibOut to a clean slate (handles peer_type change on
                // reconnect) and then do an initial full-table advertisement.
                let pt = info.peer_type;
                if let Some(aro) = adj_ribs_out_map.get_mut(&peer_ip) {
                    *aro = AdjRibOut::new(peer_id, pt);
                }

                let all_nlris: Vec<Nlri<Ipv4Addr>> =
                    loc_rib.best_routes().map(|(n, _)| n).collect();
                let rib_prefixes = all_nlris.len();

                let export_policy = export_policies
                    .get(&peer_ip)
                    .expect("peer IP missing from export_policies — this is a bug");
                let adj_rib_out = adj_ribs_out_map
                    .get_mut(&peer_ip)
                    .expect("peer IP missing from adj_ribs_out — this is a bug");
                let update_tx = update_senders
                    .get(&peer_ip)
                    .expect("peer IP missing from update_senders — this is a bug");

                for nlri in all_nlris {
                    propagate_prefix(
                        nlri,
                        &loc_rib,
                        adj_rib_out,
                        export_policy,
                        pt,
                        local_as,
                        local_bgp_id,
                        update_tx,
                    );
                }

                tracing::info!(
                    peer = %peer_ip,
                    remote_as = info.peer_as,
                    hold_time = info.hold_time,
                    peer_type = %info.peer_type,
                    rib_prefixes,
                    "session established"
                );
            }
            SessionEvent::Terminated => {
                peer_types.remove(&peer_ip);
                if let Some(ari) = adj_ribs_in_map.get_mut(&peer_ip) {
                    ari.clear();
                }

                // Snapshot affected prefixes before withdrawal so we can
                // propagate the changes to other established peers below.
                let prev_prefixes: Vec<Nlri<Ipv4Addr>> =
                    loc_rib.best_routes().map(|(n, _)| n).collect();

                loc_rib.withdraw_peer(&peer_id);

                // Reset this peer's outbound state for a clean reconnect.
                let cfg_pt = peer_config_types
                    .get(&peer_ip)
                    .copied()
                    .unwrap_or(PeerType::External);
                if let Some(aro) = adj_ribs_out_map.get_mut(&peer_ip) {
                    *aro = AdjRibOut::new(peer_id, cfg_pt);
                }

                // Tell all other established peers about the best-path changes
                // caused by this teardown.
                let other_peers: Vec<Ipv4Addr> = peer_types
                    .keys()
                    .copied()
                    .filter(|&ip| ip != peer_ip)
                    .collect();

                for other_ip in other_peers {
                    let other_type = peer_types
                        .get(&other_ip)
                        .copied()
                        .unwrap_or(PeerType::External);
                    let export_policy = export_policies
                        .get(&other_ip)
                        .expect("peer IP missing from export_policies — this is a bug");
                    let adj_rib_out = adj_ribs_out_map
                        .get_mut(&other_ip)
                        .expect("peer IP missing from adj_ribs_out — this is a bug");
                    let update_tx = update_senders
                        .get(&other_ip)
                        .expect("peer IP missing from update_senders — this is a bug");

                    for &nlri in &prev_prefixes {
                        propagate_prefix(
                            nlri,
                            &loc_rib,
                            adj_rib_out,
                            export_policy,
                            other_type,
                            local_as,
                            local_bgp_id,
                            update_tx,
                        );
                    }
                }

                tracing::info!(
                    peer = %peer_ip,
                    rib_size = loc_rib.len(),
                    "session terminated"
                );
            }
            SessionEvent::RouteUpdate(msg) => {
                let peer_type = peer_types
                    .get(&peer_ip)
                    .copied()
                    .unwrap_or(PeerType::External);

                // Collect affected prefixes before moving msg into handle_update.
                let affected: Vec<Nlri<Ipv4Addr>> = msg
                    .withdrawn
                    .iter()
                    .chain(msg.announced.iter())
                    .copied()
                    .collect();

                // Both maps are built from cfg.peers at startup — every peer has an entry.
                let policy = import_policies
                    .get(&peer_ip)
                    .expect("peer IP missing from import_policies — this is a bug");
                let adj_rib_in = adj_ribs_in_map
                    .get_mut(&peer_ip)
                    .expect("peer IP missing from adj_ribs_in — this is a bug");

                handle_update(peer_id, msg, adj_rib_in, &mut loc_rib, policy, peer_type);

                // Propagate best-path changes for affected prefixes to all
                // established peers (iBGP split-horizon is enforced by AdjRibOut).
                let established_peers: Vec<Ipv4Addr> = peer_types.keys().copied().collect();

                for other_ip in established_peers {
                    let other_type = peer_types
                        .get(&other_ip)
                        .copied()
                        .unwrap_or(PeerType::External);
                    let export_policy = export_policies
                        .get(&other_ip)
                        .expect("peer IP missing from export_policies — this is a bug");
                    let adj_rib_out = adj_ribs_out_map
                        .get_mut(&other_ip)
                        .expect("peer IP missing from adj_ribs_out — this is a bug");
                    let update_tx = update_senders
                        .get(&other_ip)
                        .expect("peer IP missing from update_senders — this is a bug");

                    for &nlri in &affected {
                        propagate_prefix(
                            nlri,
                            &loc_rib,
                            adj_rib_out,
                            export_policy,
                            other_type,
                            local_as,
                            local_bgp_id,
                            update_tx,
                        );
                    }
                }
            }
        }
    }
}

/// Re-evaluates all routes stored in `adj_rib_in` against `policy` and
/// reconciles `loc_rib` with the result.
///
/// This is soft reconfiguration: when the import policy for a peer changes,
/// call this instead of resetting the session. Routes that the new policy
/// accepts are (re-)inserted into `loc_rib` with any attribute modifications
/// the policy applies. Routes that the new policy rejects are withdrawn from
/// `loc_rib` if they were previously accepted.
///
/// The raw routes in `adj_rib_in` are never modified — they always reflect
/// what the peer actually advertised.
pub fn reapply_import_policy(
    peer: PeerId,
    adj_rib_in: &AdjRibIn<Ipv4Addr>,
    loc_rib: &mut LocRib<Ipv4Addr>,
    policy: &Policy<Route<Ipv4Addr>>,
) {
    let mut accepted = 0usize;
    let mut rejected = 0usize;

    for (nlri, raw_route) in adj_rib_in.routes() {
        let mut route = raw_route.clone();
        match policy.evaluate(&mut route) {
            Decision::Accept => {
                loc_rib.insert(peer, route);
                accepted += 1;
            }
            Decision::Reject | Decision::Next => {
                loc_rib.withdraw(&peer, nlri);
                rejected += 1;
            }
        }
    }

    tracing::info!(
        peer = %peer,
        accepted,
        rejected,
        rib_size = loc_rib.len(),
        "soft reconfig complete"
    );
}

fn handle_update(
    peer: PeerId,
    msg: UpdateMessage,
    adj_rib_in: &mut AdjRibIn<Ipv4Addr>,
    loc_rib: &mut LocRib<Ipv4Addr>,
    policy: &Policy<Route<Ipv4Addr>>,
    peer_type: PeerType,
) {
    let withdrawn_count = msg.withdrawn.len();
    let announced_count = msg.announced.len();

    for nlri in &msg.withdrawn {
        adj_rib_in.withdraw(nlri);
        loc_rib.withdraw(&peer, nlri);
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
            let mut builder = RouteBuilder::new(nlri, origin, as_path.clone()).peer_type(peer_type);
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

            let raw = builder.build();
            // Store the pre-policy route for soft reconfiguration.
            adj_rib_in.insert(raw.clone());

            // Apply import policy to a working copy; only insert if accepted.
            let mut route = raw;
            match policy.evaluate(&mut route) {
                Decision::Accept => {
                    loc_rib.insert(peer, route);
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
        rib_size = loc_rib.len(),
        "processed UPDATE"
    );
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use pathvector_policy::{
        Accept, ActionSequence, AnyCondition, CommunityCondition, DefaultAction, Policy, Reject,
        SetLocalPref, Term,
    };
    use pathvector_types::{
        Aggregator, Asn, Community, ExtendedCommunity, LargeCommunity, LocalPref as LP, Nlri,
    };

    use super::*;

    fn peer() -> PeerId {
        PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    }

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn accept_all() -> Policy<Route<Ipv4Addr>> {
        Policy::new(DefaultAction::Accept)
    }

    fn reject_all() -> Policy<Route<Ipv4Addr>> {
        Policy::new(DefaultAction::Reject)
    }

    fn fresh_ari() -> AdjRibIn<Ipv4Addr> {
        AdjRibIn::new(peer())
    }

    // ── basic handle_update behaviour ─────────────────────────────────────────

    #[test]
    fn test_handle_update_inserts_route_with_all_attributes() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
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
                PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::route_target_as2(
                    65000, 1,
                )]),
                PathAttribute::AtomicAggregate,
                PathAttribute::Aggregator(Aggregator::new(
                    Asn::new(65001),
                    Ipv4Addr::new(1, 1, 1, 1),
                )),
            ],
            announced: vec![nlri("192.168.0.0/16")],
        };
        handle_update(
            peer(),
            msg,
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );

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
        let mut ari = fresh_ari();
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
            &mut ari,
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
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(rib.is_empty());
        assert!(ari.is_empty());
    }

    #[test]
    fn test_handle_update_empty_announced_is_noop() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::Origin(Origin::Igp)],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(rib.is_empty());
        assert!(ari.is_empty());
    }

    #[test]
    fn test_handle_update_unknown_attribute_is_skipped() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::Unknown {
                        flags: 0x80,
                        type_code: 255,
                        value: vec![1, 2, 3],
                    },
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
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
        let mut ari = fresh_ari();
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
            &mut ari,
            &mut rib,
            &reject_all(),
            PeerType::External,
        );
        assert!(rib.is_empty());
    }

    #[test]
    fn test_accept_all_policy_passes_all_routes() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
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
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 2);
    }

    #[test]
    fn test_policy_modifies_route_before_insert() {
        let mut policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Reject);
        policy.add_term(Term::new(
            AnyCondition,
            ActionSequence::new()
                .then(SetLocalPref::new(LP::new(200)))
                .then(Accept),
        ));

        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
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
            &mut ari,
            &mut rib,
            &policy,
            PeerType::External,
        );

        let route = rib.best(&nlri("10.0.0.0/8")).unwrap();
        assert_eq!(route.local_pref, Some(LP::new(200)));
    }

    #[test]
    fn test_policy_partial_reject_only_accepted_routes_inserted() {
        let blocked = Community::from_parts(65001, 1);
        let mut policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Accept);
        policy.add_term(Term::new(CommunityCondition::new(blocked), Reject));

        let mut rib = LocRib::new();
        let mut ari = fresh_ari();

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
            &mut ari,
            &mut rib,
            &policy,
            PeerType::External,
        );

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
            &mut ari,
            &mut rib,
            &policy,
            PeerType::External,
        );

        assert!(
            rib.best(&nlri("10.0.0.0/8")).is_none(),
            "blocked route must not be in RIB"
        );
        assert!(
            rib.best(&nlri("192.168.0.0/16")).is_some(),
            "clean route must be in RIB"
        );
    }

    #[test]
    fn test_peer_type_tagged_on_route() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
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
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::Internal,
        );
        let route = rib.best(&nlri("10.0.0.0/8")).unwrap();
        assert_eq!(route.peer_type, PeerType::Internal);
    }

    // ── Adj-RIB-In pre-policy store ───────────────────────────────────────────

    #[test]
    fn test_adj_rib_in_stores_raw_route_even_when_rejected() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
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
            &mut ari,
            &mut rib,
            &reject_all(),
            PeerType::External,
        );
        // Rejected by import policy → not in LocRib
        assert!(rib.is_empty());
        // But still stored in Adj-RIB-In so soft reconfig can revisit it
        assert_eq!(ari.len(), 1);
        assert!(ari.get(&nlri("10.0.0.0/8")).is_some());
    }

    #[test]
    fn test_adj_rib_in_stores_raw_attributes_before_policy_modification() {
        // Policy sets LOCAL_PREF 200. AdjRibIn should hold the original (no LP).
        let mut policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Reject);
        policy.add_term(Term::new(
            AnyCondition,
            ActionSequence::new()
                .then(SetLocalPref::new(LP::new(200)))
                .then(Accept),
        ));

        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
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
            &mut ari,
            &mut rib,
            &policy,
            PeerType::External,
        );

        // LocRib has the policy-modified route
        assert_eq!(
            rib.best(&nlri("10.0.0.0/8")).unwrap().local_pref,
            Some(LP::new(200))
        );
        // AdjRibIn has the raw route — no LOCAL_PREF set by policy
        assert_eq!(ari.get(&nlri("10.0.0.0/8")).unwrap().local_pref, None);
    }

    #[test]
    fn test_adj_rib_in_withdraw_clears_both_tables() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
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
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(ari.len(), 1);
        assert_eq!(rib.len(), 1);

        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![nlri("10.0.0.0/8")],
                attributes: vec![],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(ari.is_empty());
        assert!(rib.is_empty());
    }

    // ── soft reconfiguration ──────────────────────────────────────────────────

    #[test]
    fn test_reapply_accepts_previously_rejected_route() {
        // Route was rejected on arrival. New policy accepts it — it should
        // appear in LocRib after reapply without a session reset.
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
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
            &mut ari,
            &mut rib,
            &reject_all(),
            PeerType::External,
        );
        assert!(rib.is_empty());

        reapply_import_policy(peer(), &ari, &mut rib, &accept_all());
        assert!(rib.best(&nlri("10.0.0.0/8")).is_some());
    }

    #[test]
    fn test_reapply_rejects_previously_accepted_route() {
        // Route was accepted on arrival. New policy rejects it — it should
        // disappear from LocRib after reapply.
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
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
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(rib.best(&nlri("10.0.0.0/8")).is_some());

        reapply_import_policy(peer(), &ari, &mut rib, &reject_all());
        assert!(rib.best(&nlri("10.0.0.0/8")).is_none());
    }

    #[test]
    fn test_reapply_applies_new_policy_modifications() {
        // Route arrived without LOCAL_PREF. New policy sets LP 300.
        // After reapply, LocRib should have the modified version; AdjRibIn unchanged.
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
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
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.best(&nlri("10.0.0.0/8")).unwrap().local_pref, None);

        let mut new_policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Reject);
        new_policy.add_term(Term::new(
            AnyCondition,
            ActionSequence::new()
                .then(SetLocalPref::new(LP::new(300)))
                .then(Accept),
        ));

        reapply_import_policy(peer(), &ari, &mut rib, &new_policy);
        assert_eq!(
            rib.best(&nlri("10.0.0.0/8")).unwrap().local_pref,
            Some(LP::new(300))
        );
        // Raw route in AdjRibIn is still unmodified
        assert_eq!(ari.get(&nlri("10.0.0.0/8")).unwrap().local_pref, None);
    }

    #[test]
    fn test_reapply_partial_accept_reject() {
        // Two routes: policy accepts one and rejects the other.
        let blocked = Community::from_parts(65001, 1);
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();

        // Accept both with the initial policy
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
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
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
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 2);

        // New policy: reject anything with the blocked community
        let mut new_policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Accept);
        new_policy.add_term(Term::new(CommunityCondition::new(blocked), Reject));

        reapply_import_policy(peer(), &ari, &mut rib, &new_policy);
        assert!(
            rib.best(&nlri("10.0.0.0/8")).is_none(),
            "blocked route must be withdrawn"
        );
        assert!(
            rib.best(&nlri("192.168.0.0/16")).is_some(),
            "clean route must remain"
        );
    }

    // ── prepare_outbound ──────────────────────────────────────────────────────

    fn bgp_id() -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, 1)
    }

    fn ebgp_route_with_lp(prefix: &str) -> Route<Ipv4Addr> {
        RouteBuilder::new(
            nlri(prefix),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65002)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 2)))
        .local_pref(LP::new(200))
        .peer_type(PeerType::External)
        .build()
    }

    fn ibgp_route(prefix: &str) -> Route<Ipv4Addr> {
        RouteBuilder::new(
            nlri(prefix),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65002)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 2)))
        .local_pref(LP::new(200))
        .peer_type(PeerType::Internal)
        .build()
    }

    #[test]
    fn test_prepare_outbound_ebgp_prepends_local_as() {
        let route = ebgp_route_with_lp("10.0.0.0/8");
        let out = prepare_outbound(route, PeerType::External, 65001, bgp_id());
        // Local AS 65001 is prepended; original AS 65002 is now last.
        assert_eq!(out.as_path.path_length(), 2);
        assert!(out.as_path.contains(Asn::new(65001)));
        assert!(out.as_path.contains(Asn::new(65002)));
    }

    #[test]
    fn test_prepare_outbound_ebgp_rewrites_next_hop() {
        let route = ebgp_route_with_lp("10.0.0.0/8");
        let out = prepare_outbound(route, PeerType::External, 65001, bgp_id());
        assert_eq!(out.next_hop, Some(NextHop::V4(bgp_id())));
    }

    #[test]
    fn test_prepare_outbound_ebgp_strips_local_pref() {
        let route = ebgp_route_with_lp("10.0.0.0/8");
        let out = prepare_outbound(route, PeerType::External, 65001, bgp_id());
        assert!(
            out.local_pref.is_none(),
            "LOCAL_PREF must be stripped for eBGP"
        );
    }

    #[test]
    fn test_prepare_outbound_ibgp_preserves_attributes() {
        let route = ibgp_route("10.0.0.0/8");
        let out = prepare_outbound(route.clone(), PeerType::Internal, 65001, bgp_id());
        // iBGP: nothing modified.
        assert_eq!(out.as_path.path_length(), route.as_path.path_length());
        assert_eq!(out.local_pref, route.local_pref);
        assert_eq!(out.next_hop, route.next_hop);
    }

    // ── route_to_update ───────────────────────────────────────────────────────

    #[test]
    fn test_route_to_update_contains_mandatory_attributes() {
        let route = RouteBuilder::new(
            nlri("10.0.0.0/8"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65001)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .build();

        let msg = route_to_update(route);
        assert_eq!(msg.announced, vec![nlri("10.0.0.0/8")]);
        assert!(msg.withdrawn.is_empty());
        let has_origin = msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::Origin(_)));
        let has_aspath = msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::AsPath(_)));
        let has_nexthop = msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::NextHop(_)));
        assert!(has_origin);
        assert!(has_aspath);
        assert!(has_nexthop);
    }

    #[test]
    fn test_route_to_update_omits_absent_optional_attributes() {
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new()).build();
        let msg = route_to_update(route);
        let has_lp = msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(_)));
        let has_med = msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::Med(_)));
        assert!(!has_lp, "absent LOCAL_PREF must not appear in UPDATE");
        assert!(!has_med, "absent MED must not appear in UPDATE");
    }

    // ── propagate_prefix ──────────────────────────────────────────────────────

    fn ebgp_out_peer() -> (PeerId, AdjRibOut<Ipv4Addr>) {
        let p = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        (p, AdjRibOut::new(p, PeerType::External))
    }

    fn ibgp_out_peer() -> (PeerId, AdjRibOut<Ipv4Addr>) {
        let p = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)));
        (p, AdjRibOut::new(p, PeerType::Internal))
    }

    #[test]
    fn test_propagate_prefix_sends_update_for_new_route() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        propagate_prefix(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );

        let msg = rx.try_recv().expect("should have queued an UPDATE");
        assert!(
            !msg.announced.is_empty(),
            "UPDATE must contain announced NLRIs"
        );
        assert_eq!(msg.announced[0], nlri("10.0.0.0/8"));
    }

    #[test]
    fn test_propagate_prefix_no_send_when_route_unchanged() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        // First call populates AdjRibOut.
        propagate_prefix(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let _ = rx.try_recv();

        // Second call with same best route — no UPDATE should be queued.
        propagate_prefix(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(
            rx.try_recv().is_err(),
            "identical route must not produce a second UPDATE"
        );
    }

    #[test]
    fn test_propagate_prefix_sends_withdraw_when_route_removed() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        // Advertise the route.
        propagate_prefix(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let _ = rx.try_recv();

        // Remove the route from the RIB.
        rib.withdraw(&peer(), &nlri("10.0.0.0/8"));

        // Should now queue a WITHDRAW.
        propagate_prefix(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let msg = rx.try_recv().expect("should have queued a WITHDRAW");
        assert!(!msg.withdrawn.is_empty(), "message should be a WITHDRAW");
        assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));
        assert!(msg.announced.is_empty());
    }

    #[test]
    fn test_propagate_prefix_sends_withdraw_when_export_policy_rejects() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        // Initial advertisement.
        propagate_prefix(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let _ = rx.try_recv();

        // Policy now rejects — must send WITHDRAW for the previously advertised route.
        propagate_prefix(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &reject_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let msg = rx.try_recv().expect("should have queued a WITHDRAW");
        assert!(!msg.withdrawn.is_empty());
        assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));
    }

    #[test]
    fn test_propagate_prefix_no_withdraw_for_never_advertised_route() {
        let (_, mut aro) = ebgp_out_peer();
        let rib = LocRib::<Ipv4Addr>::new();
        let (tx, mut rx) = mpsc::channel(16);

        // Nothing was ever advertised; no message should be sent.
        propagate_prefix(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &reject_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(
            rx.try_recv().is_err(),
            "no message expected for a route that was never advertised"
        );
    }

    #[test]
    fn test_propagate_prefix_ibgp_split_horizon_no_send() {
        // An iBGP-learned route must not be re-advertised to another iBGP peer.
        let mut rib = LocRib::new();
        rib.insert(peer(), ibgp_route("10.0.0.0/8"));
        let (_, mut aro) = ibgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        propagate_prefix(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::Internal,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(
            rx.try_recv().is_err(),
            "iBGP split-horizon must suppress re-advertisement"
        );
        assert!(
            aro.is_empty(),
            "AdjRibOut must remain empty after split-horizon suppression"
        );
    }

    #[test]
    fn test_propagate_prefix_ebgp_prepends_local_as_in_wire_message() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        propagate_prefix(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );

        let msg = rx.try_recv().unwrap();
        let aspath_attr = msg
            .attributes
            .iter()
            .find_map(|a| {
                if let PathAttribute::AsPath(p) = a {
                    Some(p.clone())
                } else {
                    None
                }
            })
            .expect("UPDATE must carry AS_PATH");
        assert!(
            aspath_attr.contains(Asn::new(65001)),
            "local AS must be prepended"
        );
    }
}

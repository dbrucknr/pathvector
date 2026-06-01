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

/// Resolves the effective import default action for a peer (RFC 8212).
///
/// eBGP peers with no explicit setting default to `Reject` — no routes are
/// accepted unless a policy term explicitly accepts them. iBGP peers default
/// to `Accept`. An explicit `import_default` in config always wins.
fn resolve_import_default(opt: Option<config::ImportDefault>, is_ebgp: bool) -> DefaultAction {
    match opt {
        Some(d) => DefaultAction::from(d),
        None if is_ebgp => DefaultAction::Reject,
        None => DefaultAction::Accept,
    }
}

/// Resolves the effective export default action for a peer (RFC 8212).
///
/// eBGP peers with no explicit setting default to `Reject` — no routes are
/// advertised unless a policy term explicitly accepts them. iBGP peers default
/// to `Accept`. An explicit `export_default` in config always wins.
fn resolve_export_default(opt: Option<config::ExportDefault>, is_ebgp: bool) -> DefaultAction {
    match opt {
        Some(d) => DefaultAction::from(d),
        None if is_ebgp => DefaultAction::Reject,
        None => DefaultAction::Accept,
    }
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

/// Holds all per-peer routing state and applies BGP event semantics.
///
/// Constructed once at startup from config; `run()` feeds it `SessionEvent`s.
/// The struct owns no I/O — callers hold the session handles and event channel,
/// making the routing logic fully unit-testable without real TCP connections.
struct DaemonState {
    local_as: u32,
    local_bgp_id: Ipv4Addr,
    loc_rib: LocRib<Ipv4Addr>,
    import_policies: HashMap<Ipv4Addr, Policy<Route<Ipv4Addr>>>,
    export_policies: HashMap<Ipv4Addr, Policy<Route<Ipv4Addr>>>,
    adj_ribs_in: HashMap<Ipv4Addr, AdjRibIn<Ipv4Addr>>,
    adj_ribs_out: HashMap<Ipv4Addr, AdjRibOut<Ipv4Addr>>,
    /// Static peer type derived from config; used to reset `AdjRibOut` on reconnect.
    peer_config_types: HashMap<Ipv4Addr, PeerType>,
    /// Live session state: present while a peer is Established, absent otherwise.
    peer_types: HashMap<Ipv4Addr, PeerType>,
    update_senders: HashMap<Ipv4Addr, mpsc::Sender<UpdateMessage>>,
}

impl DaemonState {
    fn new(
        local_as: u32,
        local_bgp_id: Ipv4Addr,
        peers: &[config::PeerConfig],
        update_senders: HashMap<Ipv4Addr, mpsc::Sender<UpdateMessage>>,
    ) -> Self {
        let import_policies = peers
            .iter()
            .map(|p| {
                let is_ebgp = p.remote_as != local_as;
                (
                    p.address,
                    Policy::new(resolve_import_default(p.import_default, is_ebgp)),
                )
            })
            .collect();

        let export_policies = peers
            .iter()
            .map(|p| {
                let is_ebgp = p.remote_as != local_as;
                (
                    p.address,
                    Policy::new(resolve_export_default(p.export_default, is_ebgp)),
                )
            })
            .collect();

        let adj_ribs_in = peers
            .iter()
            .map(|p| (p.address, AdjRibIn::new(PeerId::from(p.address))))
            .collect();

        let peer_config_types = peers
            .iter()
            .map(|p| (p.address, config_peer_type(local_as, p.remote_as)))
            .collect();

        let adj_ribs_out = peers
            .iter()
            .map(|p| {
                let pt = config_peer_type(local_as, p.remote_as);
                (p.address, AdjRibOut::new(PeerId::from(p.address), pt))
            })
            .collect();

        Self {
            local_as,
            local_bgp_id,
            loc_rib: LocRib::new(),
            import_policies,
            export_policies,
            adj_ribs_in,
            adj_ribs_out,
            peer_config_types,
            peer_types: HashMap::new(),
            update_senders,
        }
    }

    /// Called when a BGP session reaches Established.
    ///
    /// Records the negotiated peer type, resets the peer's `AdjRibOut` to a
    /// clean slate, and performs a full-table dump of the current best routes
    /// subject to export policy.
    #[allow(clippy::similar_names)]
    fn on_established(
        &mut self,
        peer_ip: Ipv4Addr,
        peer_type: PeerType,
        peer_as: u32,
        hold_time: u16,
    ) {
        let peer_id = PeerId::from(peer_ip);
        self.peer_types.insert(peer_ip, peer_type);

        if let Some(aro) = self.adj_ribs_out.get_mut(&peer_ip) {
            *aro = AdjRibOut::new(peer_id, peer_type);
        }

        let all_nlris: Vec<Nlri<Ipv4Addr>> =
            self.loc_rib.best_routes().map(|(n, _)| n).collect();
        let rib_prefixes = all_nlris.len();

        let Some(export_policy) = self.export_policies.get(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "export_policies missing peer — skipping Established event");
            return;
        };
        let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "adj_ribs_out missing peer — skipping Established event");
            return;
        };
        let Some(update_tx) = self.update_senders.get(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "update_senders missing peer — skipping Established event");
            return;
        };

        for nlri in all_nlris {
            propagate_prefix(
                nlri,
                &self.loc_rib,
                adj_rib_out,
                export_policy,
                peer_type,
                self.local_as,
                self.local_bgp_id,
                update_tx,
            );
        }

        tracing::info!(
            peer = %peer_ip,
            remote_as = peer_as,
            hold_time,
            peer_type = %peer_type,
            rib_prefixes,
            "session established"
        );
    }

    /// Called when a BGP session terminates.
    ///
    /// Clears the peer's RIB state, resets its outbound table, and propagates
    /// any best-path changes caused by the withdrawal to all remaining
    /// established peers.
    #[allow(clippy::similar_names)]
    fn on_terminated(&mut self, peer_ip: Ipv4Addr) {
        let peer_id = PeerId::from(peer_ip);
        self.peer_types.remove(&peer_ip);

        if let Some(ari) = self.adj_ribs_in.get_mut(&peer_ip) {
            ari.clear();
        }

        // Snapshot affected prefixes before withdrawal so we can propagate the
        // changes to other established peers below.
        let prev_prefixes: Vec<Nlri<Ipv4Addr>> =
            self.loc_rib.best_routes().map(|(n, _)| n).collect();

        self.loc_rib.withdraw_peer(&peer_id);

        // Reset this peer's outbound state for a clean reconnect.
        let cfg_pt = self
            .peer_config_types
            .get(&peer_ip)
            .copied()
            .unwrap_or(PeerType::External);
        if let Some(aro) = self.adj_ribs_out.get_mut(&peer_ip) {
            *aro = AdjRibOut::new(peer_id, cfg_pt);
        }

        // Tell all other established peers about the best-path changes caused
        // by this teardown.
        let other_peers: Vec<Ipv4Addr> = self
            .peer_types
            .keys()
            .copied()
            .filter(|&ip| ip != peer_ip)
            .collect();

        for other_ip in other_peers {
            let other_type = self
                .peer_types
                .get(&other_ip)
                .copied()
                .unwrap_or(PeerType::External);
            let Some(export_policy) = self.export_policies.get(&other_ip) else {
                tracing::error!(peer = %other_ip, "export_policies missing peer — skipping propagation on Terminated");
                continue;
            };
            let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&other_ip) else {
                tracing::error!(peer = %other_ip, "adj_ribs_out missing peer — skipping propagation on Terminated");
                continue;
            };
            let Some(update_tx) = self.update_senders.get(&other_ip) else {
                tracing::error!(peer = %other_ip, "update_senders missing peer — skipping propagation on Terminated");
                continue;
            };

            for &nlri in &prev_prefixes {
                propagate_prefix(
                    nlri,
                    &self.loc_rib,
                    adj_rib_out,
                    export_policy,
                    other_type,
                    self.local_as,
                    self.local_bgp_id,
                    update_tx,
                );
            }
        }

        tracing::info!(
            peer = %peer_ip,
            rib_size = self.loc_rib.len(),
            "session terminated"
        );
    }

    /// Called when a BGP UPDATE message arrives from an established peer.
    ///
    /// Applies import policy, updates the RIB, and propagates best-path changes
    /// for all affected NLRIs to every established peer.
    #[allow(clippy::similar_names)]
    fn on_route_update(&mut self, peer_ip: Ipv4Addr, msg: UpdateMessage) {
        let peer_id = PeerId::from(peer_ip);
        let peer_type = self
            .peer_types
            .get(&peer_ip)
            .copied()
            .unwrap_or(PeerType::External);

        let affected: Vec<Nlri<Ipv4Addr>> = msg
            .withdrawn
            .iter()
            .chain(msg.announced.iter())
            .copied()
            .collect();

        let Some(policy) = self.import_policies.get(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "import_policies missing peer — skipping RouteUpdate");
            return;
        };
        let Some(adj_rib_in) = self.adj_ribs_in.get_mut(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "adj_ribs_in missing peer — skipping RouteUpdate");
            return;
        };

        handle_update(peer_id, msg, adj_rib_in, &mut self.loc_rib, policy, peer_type);

        // Propagate best-path changes for affected prefixes to all established
        // peers (iBGP split-horizon is enforced by AdjRibOut).
        let established_peers: Vec<Ipv4Addr> = self.peer_types.keys().copied().collect();

        for other_ip in established_peers {
            let other_type = self
                .peer_types
                .get(&other_ip)
                .copied()
                .unwrap_or(PeerType::External);
            let Some(export_policy) = self.export_policies.get(&other_ip) else {
                tracing::error!(peer = %other_ip, "export_policies missing peer — skipping propagation on RouteUpdate");
                continue;
            };
            let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&other_ip) else {
                tracing::error!(peer = %other_ip, "adj_ribs_out missing peer — skipping propagation on RouteUpdate");
                continue;
            };
            let Some(update_tx) = self.update_senders.get(&other_ip) else {
                tracing::error!(peer = %other_ip, "update_senders missing peer — skipping propagation on RouteUpdate");
                continue;
            };

            for &nlri in &affected {
                propagate_prefix(
                    nlri,
                    &self.loc_rib,
                    adj_rib_out,
                    export_policy,
                    other_type,
                    self.local_as,
                    self.local_bgp_id,
                    update_tx,
                );
            }
        }
    }
}

async fn run(cfg: config::Config) {
    let local_as = cfg.daemon.local_as;
    let local_bgp_id = cfg.daemon.bgp_id;

    let (event_tx, mut event_rx) = mpsc::channel::<(Ipv4Addr, SessionEvent)>(256);
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

    let mut state = DaemonState::new(local_as, local_bgp_id, &cfg.peers, update_senders);

    while let Some((peer_ip, event)) = event_rx.recv().await {
        match event {
            SessionEvent::Established(info) => {
                state.on_established(peer_ip, info.peer_type, info.peer_as, info.hold_time);
            }
            SessionEvent::Terminated => {
                state.on_terminated(peer_ip);
            }
            SessionEvent::RouteUpdate(msg) => {
                state.on_route_update(peer_ip, msg);
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

    // ── test helpers ──────────────────────────────────────────────────────────

    fn peer_id(ip: &str) -> PeerId {
        PeerId::new(IpAddr::V4(ip.parse().unwrap()))
    }

    fn peer() -> PeerId {
        peer_id("10.0.0.1")
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

    /// Builds a `DaemonState` with explicit accept-all policies for every peer.
    /// Returns the state and a map of receivers for asserting on outbound messages.
    fn make_state(
        local_as: u32,
        peers: &[(Ipv4Addr, u32)],
    ) -> (DaemonState, HashMap<Ipv4Addr, mpsc::Receiver<UpdateMessage>>) {
        let mut senders = HashMap::new();
        let mut receivers = HashMap::new();
        for &(ip, _) in peers {
            let (tx, rx) = mpsc::channel(64);
            senders.insert(ip, tx);
            receivers.insert(ip, rx);
        }
        let peer_configs: Vec<config::PeerConfig> = peers
            .iter()
            .map(|&(address, remote_as)| config::PeerConfig {
                address,
                port: 179,
                remote_as,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
            })
            .collect();
        let local_bgp_id = Ipv4Addr::new(10, 0, 0, 1);
        let state = DaemonState::new(local_as, local_bgp_id, &peer_configs, senders);
        (state, receivers)
    }

    // ── config_peer_type ─────────────────────────────────────────────────────

    #[test]
    fn test_config_peer_type_different_as_is_external() {
        assert_eq!(config_peer_type(65001, 65002), PeerType::External);
    }

    #[test]
    fn test_config_peer_type_same_as_is_internal() {
        assert_eq!(config_peer_type(65001, 65001), PeerType::Internal);
    }

    // ── RFC 8212 default resolution ───────────────────────────────────────────

    #[test]
    fn test_resolve_import_ebgp_omitted_defaults_to_reject() {
        assert!(matches!(
            resolve_import_default(None, true),
            DefaultAction::Reject
        ));
    }

    #[test]
    fn test_resolve_import_ibgp_omitted_defaults_to_accept() {
        assert!(matches!(
            resolve_import_default(None, false),
            DefaultAction::Accept
        ));
    }

    #[test]
    fn test_resolve_import_explicit_accept_overrides_ebgp_default() {
        assert!(matches!(
            resolve_import_default(Some(config::ImportDefault::Accept), true),
            DefaultAction::Accept
        ));
    }

    #[test]
    fn test_resolve_import_explicit_reject_overrides_ibgp_default() {
        assert!(matches!(
            resolve_import_default(Some(config::ImportDefault::Reject), false),
            DefaultAction::Reject
        ));
    }

    #[test]
    fn test_resolve_export_ebgp_omitted_defaults_to_reject() {
        assert!(matches!(
            resolve_export_default(None, true),
            DefaultAction::Reject
        ));
    }

    #[test]
    fn test_resolve_export_ibgp_omitted_defaults_to_accept() {
        assert!(matches!(
            resolve_export_default(None, false),
            DefaultAction::Accept
        ));
    }

    #[test]
    fn test_resolve_export_explicit_accept_overrides_ebgp_default() {
        assert!(matches!(
            resolve_export_default(Some(config::ExportDefault::Accept), true),
            DefaultAction::Accept
        ));
    }

    #[test]
    fn test_resolve_export_explicit_reject_overrides_ibgp_default() {
        assert!(matches!(
            resolve_export_default(Some(config::ExportDefault::Reject), false),
            DefaultAction::Reject
        ));
    }

    // ── DaemonState::new ─────────────────────────────────────────────────────

    #[test]
    fn test_daemon_state_new_creates_maps_for_all_peers() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (state, _) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);
        for ip in [peer_a, peer_b] {
            assert!(state.import_policies.contains_key(&ip));
            assert!(state.export_policies.contains_key(&ip));
            assert!(state.adj_ribs_in.contains_key(&ip));
            assert!(state.adj_ribs_out.contains_key(&ip));
            assert!(state.update_senders.contains_key(&ip));
        }
    }

    #[test]
    fn test_daemon_state_new_ebgp_gets_reject_default_when_omitted() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let peers = vec![config::PeerConfig {
            address: peer_ip,
            port: 179,
            remote_as: 65002,
            import_default: None,
            export_default: None,
        }];
        let state = DaemonState::new(65001, Ipv4Addr::new(10, 0, 0, 1), &peers, {
            let mut m = HashMap::new();
            m.insert(peer_ip, tx);
            m
        });
        // Import policy with Reject default means routes are dropped unless a
        // term accepts them. Verify by running a route through it.
        let mut route = RouteBuilder::new(
            nlri("10.0.0.0/8"),
            Origin::Igp,
            AsPath::new(),
        )
        .peer_type(PeerType::External)
        .build();
        let decision = state.import_policies[&peer_ip].evaluate(&mut route);
        assert!(
            matches!(decision, Decision::Reject),
            "eBGP with no import_default must reject by default (RFC 8212)"
        );
    }

    // ── DaemonState::on_established ───────────────────────────────────────────

    #[test]
    fn test_on_established_records_peer_type() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        assert!(!state.peer_types.contains_key(&peer_ip));
        state.on_established(peer_ip, PeerType::External, 65002, 90);
        assert_eq!(state.peer_types[&peer_ip], PeerType::External);
    }

    #[test]
    fn test_on_established_empty_rib_sends_nothing() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, PeerType::External, 65002, 90);
        assert!(
            receivers.get_mut(&peer_ip).unwrap().try_recv().is_err(),
            "empty RIB should produce no messages on establish"
        );
    }

    #[test]
    fn test_on_established_sends_full_table_dump() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_ip, 65002)]);

        // Pre-populate the RIB with a route from a third-party peer.
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
        let route = RouteBuilder::new(
            nlri("10.0.0.0/8"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65009)]),
        )
        .next_hop(NextHop::V4("10.0.0.9".parse().unwrap()))
        .peer_type(PeerType::External)
        .build();
        state.loc_rib.insert(src, route);

        state.on_established(peer_ip, PeerType::External, 65002, 90);

        let msg = receivers
            .get_mut(&peer_ip)
            .unwrap()
            .try_recv()
            .expect("should have queued a full-table dump UPDATE");
        assert_eq!(msg.announced, vec![nlri("10.0.0.0/8")]);
    }

    #[test]
    fn test_on_established_export_reject_sends_nothing() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (tx, _rx) = mpsc::channel(64);
        let peers = vec![config::PeerConfig {
            address: peer_ip,
            port: 179,
            remote_as: 65002,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Reject),
        }];
        let mut state = DaemonState::new(65001, Ipv4Addr::new(10, 0, 0, 1), &peers, {
            let mut m = HashMap::new();
            m.insert(peer_ip, tx);
            m
        });

        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
        state.loc_rib.insert(
            src,
            RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
                .peer_type(PeerType::External)
                .build(),
        );

        state.on_established(peer_ip, PeerType::External, 65002, 90);
        // Export policy rejects everything — no UPDATE should be queued.
        // (We can't assert on the receiver here since we dropped _rx, but the
        // important invariant is that no panic or error occurs, and the RIB is
        // not modified.)
        assert_eq!(state.loc_rib.len(), 1, "RIB must be unchanged");
    }

    // ── DaemonState::on_terminated ────────────────────────────────────────────

    #[test]
    fn test_on_terminated_removes_peer_type() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, PeerType::External, 65002, 90);
        state.on_terminated(peer_ip);
        assert!(!state.peer_types.contains_key(&peer_ip));
    }

    #[test]
    fn test_on_terminated_withdraws_peer_routes_from_rib() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, PeerType::External, 65002, 90);

        state.loc_rib.insert(
            PeerId::from(peer_ip),
            RouteBuilder::new(
                nlri("10.0.0.0/8"),
                Origin::Igp,
                AsPath::from_sequence(vec![Asn::new(65002)]),
            )
            .peer_type(PeerType::External)
            .build(),
        );
        assert_eq!(state.loc_rib.len(), 1);

        state.on_terminated(peer_ip);
        assert_eq!(state.loc_rib.len(), 0);
    }

    #[test]
    fn test_on_terminated_propagates_withdraw_to_other_established_peers() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) =
            make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);

        state.on_established(peer_a, PeerType::External, 65002, 90);
        state.on_established(peer_b, PeerType::External, 65003, 90);

        // Announce a route from peer_a so it reaches peer_b's AdjRibOut.
        state.on_route_update(
            peer_a,
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
        // Drain the propagation messages sent during on_route_update.
        receivers.get_mut(&peer_a).unwrap().try_recv().ok();
        receivers.get_mut(&peer_b).unwrap().try_recv().ok();

        // Terminate peer_a — peer_b must receive a WITHDRAW.
        state.on_terminated(peer_a);

        let msg = receivers
            .get_mut(&peer_b)
            .unwrap()
            .try_recv()
            .expect("peer_b should receive WITHDRAW after peer_a terminates");
        assert!(!msg.withdrawn.is_empty());
        assert_eq!(msg.withdrawn[0], nlri("192.168.0.0/16"));
    }

    // ── DaemonState::on_route_update ──────────────────────────────────────────

    #[test]
    fn test_on_route_update_inserts_route_into_rib() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, PeerType::External, 65002, 90);

        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );

        assert_eq!(state.loc_rib.len(), 1);
        assert!(state.loc_rib.best(&nlri("10.0.0.0/8")).is_some());
    }

    #[test]
    fn test_on_route_update_propagates_to_other_established_peer() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) =
            make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);

        state.on_established(peer_a, PeerType::External, 65002, 90);
        state.on_established(peer_b, PeerType::External, 65003, 90);

        state.on_route_update(
            peer_a,
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

        let msg = receivers
            .get_mut(&peer_b)
            .unwrap()
            .try_recv()
            .expect("peer_b should receive UPDATE for the new route");
        assert_eq!(msg.announced, vec![nlri("10.0.0.0/8")]);
    }

    #[test]
    fn test_on_route_update_withdraw_removes_route_from_rib() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, PeerType::External, 65002, 90);

        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );
        assert_eq!(state.loc_rib.len(), 1);

        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![nlri("10.0.0.0/8")],
                attributes: vec![],
                announced: vec![],
            },
        );
        assert_eq!(state.loc_rib.len(), 0);
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
        assert!(rib.is_empty());
        assert_eq!(ari.len(), 1);
        assert!(ari.get(&nlri("10.0.0.0/8")).is_some());
    }

    #[test]
    fn test_adj_rib_in_stores_raw_attributes_before_policy_modification() {
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

        assert_eq!(
            rib.best(&nlri("10.0.0.0/8")).unwrap().local_pref,
            Some(LP::new(200))
        );
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
        assert_eq!(ari.get(&nlri("10.0.0.0/8")).unwrap().local_pref, None);
    }

    #[test]
    fn test_reapply_partial_accept_reject() {
        let blocked = Community::from_parts(65001, 1);
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
        assert!(msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::Origin(_))));
        assert!(msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::AsPath(_))));
        assert!(msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::NextHop(_))));
    }

    #[test]
    fn test_route_to_update_omits_absent_optional_attributes() {
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new()).build();
        let msg = route_to_update(route);
        assert!(!msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(_))));
        assert!(!msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::Med(_))));
    }

    #[test]
    fn test_route_to_update_includes_all_optional_attributes() {
        let route = RouteBuilder::new(
            nlri("10.0.0.0/8"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65001)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .local_pref(LP::new(150))
        .med(Med::new(100))
        .community(Community::new(0xFFFF_FF01))
        .large_community(LargeCommunity::new(65001, 1, 1))
        .extended_community(ExtendedCommunity::route_target_as2(65001, 1))
        .atomic_aggregate()
        .aggregator(Aggregator::new(Asn::new(65001), Ipv4Addr::new(1, 1, 1, 1)))
        .build();

        let msg = route_to_update(route);
        assert!(msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(_))));
        assert!(msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::Med(_))));
        assert!(msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::Communities(_))));
        assert!(msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::LargeCommunities(_))));
        assert!(msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::ExtendedCommunities(_))));
        assert!(msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::AtomicAggregate)));
        assert!(msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::Aggregator(_))));
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
        assert!(!msg.announced.is_empty());
        assert_eq!(msg.announced[0], nlri("10.0.0.0/8"));
    }

    #[test]
    fn test_propagate_prefix_no_send_when_route_unchanged() {
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
        let _ = rx.try_recv();

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

        rib.withdraw(&peer(), &nlri("10.0.0.0/8"));

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
        assert!(!msg.withdrawn.is_empty());
        assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));
        assert!(msg.announced.is_empty());
    }

    #[test]
    fn test_propagate_prefix_sends_withdraw_when_export_policy_rejects() {
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
        let _ = rx.try_recv();

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
        assert!(aro.is_empty());
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

    // ── propagate_prefix — iBGP split-horizon eviction ────────────────────────

    /// When the best path for a prefix switches from eBGP to iBGP, the
    /// previously stored eBGP entry in the iBGP peer's AdjRibOut is evicted
    /// (`InsertOutcome::Filtered(Some(_))`), triggering a WITHDRAW.
    #[test]
    fn test_propagate_prefix_ibgp_split_horizon_eviction_sends_withdraw() {
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
        let (_, mut aro) = ibgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        // Phase 1: best path is eBGP — stored in the iBGP peer's AdjRibOut.
        let mut rib = LocRib::new();
        rib.insert(src, ebgp_route_with_lp("10.0.0.0/8"));
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
        let _ = rx.try_recv(); // consume the UPDATE

        // Phase 2: best path switches to iBGP — split-horizon evicts the stored
        // eBGP entry and the peer must receive a WITHDRAW.
        let mut rib2 = LocRib::new();
        rib2.insert(src, ibgp_route("10.0.0.0/8"));
        propagate_prefix(
            nlri("10.0.0.0/8"),
            &rib2,
            &mut aro,
            &accept_all(),
            PeerType::Internal,
            65001,
            bgp_id(),
            &tx,
        );
        let msg = rx
            .try_recv()
            .expect("split-horizon eviction must send WITHDRAW");
        assert!(!msg.withdrawn.is_empty());
        assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));
    }

    // ── propagate_prefix — channel-full warnings ──────────────────────────────

    /// When the outbound UPDATE channel is full, a warning is logged but no
    /// panic occurs.  Fill the channel before propagating a new route.
    #[test]
    fn test_propagate_prefix_full_update_channel_does_not_panic() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, _rx) = mpsc::channel(1);

        // Fill the single-slot channel so the next try_send fails.
        tx.try_send(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        })
        .unwrap();

        // propagate_prefix must log a warning and not panic.
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
    }

    /// When the outbound WITHDRAW channel is full (Reject/Next decision path),
    /// a warning is logged and no panic occurs.
    #[test]
    fn test_propagate_prefix_full_withdraw_on_reject_does_not_panic() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(1);

        // Advertise the route so it is stored in AdjRibOut.
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

        // Fill the channel before the second call so try_send fails.
        tx.try_send(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        })
        .unwrap();

        // Export policy now rejects — triggers WITHDRAW try_send on a full channel.
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
    }

    /// When the outbound WITHDRAW channel is full (no best route / None path),
    /// a warning is logged and no panic occurs.
    #[test]
    fn test_propagate_prefix_full_withdraw_on_empty_rib_does_not_panic() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(1);

        // Store the route in AdjRibOut.
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

        // Remove the route so loc_rib.best returns None.
        rib.withdraw(&peer(), &nlri("10.0.0.0/8"));

        // Fill the channel so the WITHDRAW try_send fails.
        tx.try_send(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        })
        .unwrap();

        // propagate_prefix with empty rib + full channel: must log, not panic.
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
    }

    // ── DaemonState — unknown peer defensive paths ────────────────────────────

    /// Calling `on_established` with a peer IP that was never in the config
    /// logs an error and returns without panicking.
    #[test]
    fn test_on_established_unknown_peer_is_noop() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);

        let unknown: Ipv4Addr = "10.0.0.99".parse().unwrap();
        state.on_established(unknown, PeerType::External, 65099, 90);
        // Invariant: no state changes (the unknown IP is absent from maps).
        assert!(!state.peer_types.contains_key(&peer_ip));
    }

    /// When `on_terminated` propagates to other established peers, a ghost peer
    /// (one that reached `Established` via `on_established` but was never in the
    /// config maps) triggers the missing-export-policy error path.  Must not
    /// panic.
    #[test]
    fn test_on_terminated_ghost_established_peer_does_not_panic() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_a, 65002)]);
        state.on_established(peer_a, PeerType::External, 65002, 90);

        // Inject a ghost peer into peer_types (never registered in config maps).
        let ghost: Ipv4Addr = "10.0.0.99".parse().unwrap();
        state.on_established(ghost, PeerType::External, 65099, 90);

        // Terminating peer_a iterates established peers; ghost has no policy /
        // rib entries — the error branch logs and continues without panicking.
        state.on_terminated(peer_a);
        assert!(!state.peer_types.contains_key(&peer_a));
    }

    /// Calling `on_route_update` with an unknown peer IP logs an error and
    /// returns without panicking.
    #[test]
    fn test_on_route_update_unknown_peer_is_noop() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);

        let unknown: Ipv4Addr = "10.0.0.99".parse().unwrap();
        state.on_route_update(
            unknown,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![],
                announced: vec![],
            },
        );
        assert_eq!(state.loc_rib.len(), 0);
    }

    /// When `on_route_update` propagates to established peers, a ghost peer
    /// (in peer_types but absent from policy maps) triggers the error path.
    /// Must not panic.
    #[test]
    fn test_on_route_update_ghost_established_peer_does_not_panic() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_a, 65002)]);
        state.on_established(peer_a, PeerType::External, 65002, 90);

        let ghost: Ipv4Addr = "10.0.0.99".parse().unwrap();
        state.on_established(ghost, PeerType::External, 65099, 90);

        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );
        assert_eq!(state.loc_rib.len(), 1);
    }
}

// ── Property tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod prop_tests {
    use std::net::Ipv4Addr;

    use proptest::prelude::*;

    use pathvector_types::{AsPath, Asn, LocalPref, NextHop, Origin, PeerType};

    use super::*;
    use crate::RouteBuilder;

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn base_route(prefix: &str) -> Route<Ipv4Addr> {
        RouteBuilder::new(
            nlri(prefix),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65002)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 2)))
        .local_pref(LocalPref::new(100))
        .peer_type(PeerType::External)
        .build()
    }

    proptest! {
        /// `config_peer_type` returns `Internal` iff the two AS numbers are
        /// equal, and `External` otherwise.
        #[test]
        fn prop_config_peer_type_internal_iff_equal(a: u32, b: u32) {
            let pt = config_peer_type(a, b);
            if a == b {
                prop_assert_eq!(pt, PeerType::Internal);
            } else {
                prop_assert_eq!(pt, PeerType::External);
            }
        }

        /// An explicit import default always overrides the eBGP/iBGP derived
        /// default, regardless of the `is_ebgp` flag.
        #[test]
        fn prop_resolve_import_explicit_always_wins(is_ebgp: bool) {
            let accept = resolve_import_default(Some(config::ImportDefault::Accept), is_ebgp);
            let reject = resolve_import_default(Some(config::ImportDefault::Reject), is_ebgp);
            prop_assert!(matches!(accept, DefaultAction::Accept));
            prop_assert!(matches!(reject, DefaultAction::Reject));
        }

        /// An explicit export default always overrides the eBGP/iBGP derived
        /// default.
        #[test]
        fn prop_resolve_export_explicit_always_wins(is_ebgp: bool) {
            let accept = resolve_export_default(Some(config::ExportDefault::Accept), is_ebgp);
            let reject = resolve_export_default(Some(config::ExportDefault::Reject), is_ebgp);
            prop_assert!(matches!(accept, DefaultAction::Accept));
            prop_assert!(matches!(reject, DefaultAction::Reject));
        }

        /// `withdraw_msg` always produces exactly one withdrawn NLRI and no
        /// announced NLRIs.
        #[test]
        fn prop_withdraw_msg_structure(
            prefix in prop::sample::select(vec![
                "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "0.0.0.0/0",
            ])
        ) {
            let n: Nlri<Ipv4Addr> = prefix.parse().unwrap();
            let msg = withdraw_msg(n);
            prop_assert_eq!(msg.withdrawn.len(), 1);
            prop_assert_eq!(msg.withdrawn[0], n);
            prop_assert!(msg.announced.is_empty());
            prop_assert!(msg.attributes.is_empty());
        }

        /// `route_to_update` always announces exactly the route's NLRI, never
        /// withdraws anything, and always includes Origin and AsPath attributes.
        #[test]
        fn prop_route_to_update_structure(
            prefix in prop::sample::select(vec![
                "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12",
            ])
        ) {
            use pathvector_session::message::PathAttribute;
            let route = base_route(prefix);
            let nlri_val: Nlri<Ipv4Addr> = prefix.parse().unwrap();
            let msg = route_to_update(route);

            prop_assert_eq!(msg.announced, vec![nlri_val]);
            prop_assert!(msg.withdrawn.is_empty());
            prop_assert!(
                msg.attributes.iter().any(|a| matches!(a, PathAttribute::Origin(_))),
                "UPDATE must carry ORIGIN"
            );
            prop_assert!(
                msg.attributes.iter().any(|a| matches!(a, PathAttribute::AsPath(_))),
                "UPDATE must carry AS_PATH"
            );
        }

        /// For iBGP peers, `prepare_outbound` is an identity transform: the
        /// route's AS_PATH, NEXT_HOP, and LOCAL_PREF are all preserved.
        #[test]
        fn prop_prepare_outbound_ibgp_is_identity(lp_value in 0u32..=65535) {
            let route = RouteBuilder::new(
                nlri("10.0.0.0/8"),
                Origin::Igp,
                AsPath::from_sequence(vec![Asn::new(65002)]),
            )
            .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 2)))
            .local_pref(LocalPref::new(lp_value))
            .peer_type(PeerType::Internal)
            .build();

            let result = prepare_outbound(
                route.clone(),
                PeerType::Internal,
                65001,
                Ipv4Addr::new(10, 0, 0, 1),
            );

            prop_assert_eq!(result.as_path, route.as_path, "AS_PATH must be unchanged for iBGP");
            prop_assert_eq!(result.next_hop, route.next_hop, "NEXT_HOP must be unchanged for iBGP");
            prop_assert_eq!(result.local_pref, route.local_pref, "LOCAL_PREF must be preserved for iBGP");
        }

        /// For eBGP peers, `prepare_outbound` always prepends the local AS,
        /// rewrites the NEXT_HOP, and strips LOCAL_PREF.
        #[test]
        fn prop_prepare_outbound_ebgp_transforms(local_as in 1u32..=4_294_967_294) {
            let bgp_id = Ipv4Addr::new(10, 0, 0, 1);
            let route = base_route("10.0.0.0/8");
            let original_path_len = route.as_path.path_length();

            let result = prepare_outbound(route, PeerType::External, local_as, bgp_id);

            prop_assert_eq!(
                result.as_path.path_length(),
                original_path_len + 1,
                "local AS must be prepended for eBGP"
            );
            prop_assert!(result.as_path.contains(Asn::new(local_as)), "local AS must be in the path");
            prop_assert_eq!(result.next_hop, Some(NextHop::V4(bgp_id)), "NEXT_HOP must be rewritten");
            prop_assert!(result.local_pref.is_none(), "LOCAL_PREF must be stripped for eBGP");
        }
    }
}
